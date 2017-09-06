#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()
struct segdesc gdt[NSEGS];


  #ifndef NONE
    uint removeFromPhysic(pde_t *pgdir,struct pagesInMem *pm);  //update due policy
    int addPage(struct pagesInMem *pm,uint va );                //update due policy
    int swapOut(uint swapedPage);                               
    int swapIn(uint page);                                      
    void clearSwapData(struct swapedMetaData* sm);            
    void clearPm(struct pagesInMem* pm);                      //update due policy
    void copyPm(struct pagesInMem* pm, struct pagesInMem* copyPm);      //update due policy
    int checkShellInit(char nm[]);            
    void deleteFromPhysic(uint va);                    //update due policy
    void deleteFromSwapMeta(struct proc *p,uint a);
    void updateAccessed();
    
    //debugging
    void printContainer(struct pagesInMem* pm);
    void printAccessCounter(struct pagesInMem* pm);

  #endif
 


// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpunum()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);

  // Map cpu, and curproc
  c->gdt[SEG_KCPU] = SEG(STA_W, &c->cpu, 8, 0);

  lgdt(c->gdt, sizeof(c->gdt));
  loadgs(SEG_KCPU << 3);
  
  // Initialize cpu-local storage.
  cpu = c;
  proc = 0;
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)p2v(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table 
    // entries, if necessary.
    *pde = v2p(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;
  
  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
// 
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP, 
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (p2v(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start, 
                (uint)k->phys_start, k->perm) < 0)
      return 0;
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(v2p(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  pushcli();
  cpu->gdt[SEG_TSS] = SEG16(STS_T32A, &cpu->ts, sizeof(cpu->ts)-1, 0);
  cpu->gdt[SEG_TSS].s = 0;
  cpu->ts.ss0 = SEG_KDATA << 3;
  cpu->ts.esp0 = (uint)proc->kstack + KSTACKSIZE;
  ltr(SEG_TSS << 3);
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");
  lcr3(v2p(p->pgdir));  // switch to new address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;
  
  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, v2p(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, p2v(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(struct proc *p,pde_t *pgdir, uint oldsz, uint newsz)
{

  char *mem;
  uint a;
  
  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    


    #ifndef NONE
    if(!p){
      goto special;
    }



    if (p && proc->numOfPsycPages + proc->swapedPages.numOfPagesInFile == MAX_TOTAL_PAGES){  //MAX PAGES ExCEDES
      panic("number of pages per process exceded");
      return 0;}
  
    if(p && proc->numOfPsycPages>=MAX_PSYC_PAGES){    //need to swap I.E MORE THEN 15 PAGES   
      if(!proc->hasSwapFile){
        cprintf("No SwapFile,Creating swap file...\n");
        createSwapFile(proc);
        proc->hasSwapFile=1;
        for(int j=0;j<MAX_PSYC_PAGES;j++){
          proc->swapedPages.pagesOffset[j]=-1;
        }

      }


      
      uint swapedPage=removeFromPhysic(pgdir,&proc->Ppages);
      swapOut(swapedPage);
    }


    
    
    special:
    #endif
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(proc,pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    mappages(pgdir, (char*)a, PGSIZE, v2p(mem), PTE_W|PTE_U);
   
    #ifndef NONE
    if(checkShellInit(proc->name)){ 
      addPage(&proc->Ppages,a);
      //proc->numOfPages++;
    }
    #endif

  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(struct proc* p,pde_t *pgdir, uint oldsz, uint newsz)
{
    
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a += (NPTENTRIES - 1) * PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = p2v(pa);
      kfree(v);
     
      #ifndef NONE
      if(p)
        deleteFromPhysic(a);
      #endif
      *pte = 0;
    }
     #ifndef NONE
      else if(p && *pte & PTE_PG){
        *pte = 0;
        deleteFromSwapMeta(p,a);
        
      }
      
      #endif
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(struct proc* p,pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(p,pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = p2v(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
   #ifndef NONE
    if(p){
      clearPm(&p->Ppages);
      clearSwapData(&p->swapedPages);
    }
  #endif
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(struct proc* p,pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  #ifndef NONE
    if(p){
      if(!(*pte & PTE_P) && (*pte & PTE_PG))
        swapIn((uint)uva);

      deleteFromPhysic((uint)uva);
    }

  #endif

  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm()) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)p2v(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, v2p(mem), flags) < 0)
      goto bad;
  }
  return d;

bad:
  freevm(proc,d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)p2v(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.

//*************************************************************************************************//

#ifndef NONE



void deleteFromPhysic(uint va){

  #ifdef LIFO
    struct pagesInMem *pm=&proc->Ppages;
    va = PGROUNDDOWN(va);
    if(!pm->top){
      return;
    }
    int page = 0;
    for(; page < pm->top; page++){
      if(pm->container[page] == va)
        goto rearage;
    }
    return;
    rearage:
    for(;page < pm->top; page++)
      pm->container[page] = pm->container[page+1];
    pm->container[pm->top] = -1;
    pm->top--;
    proc->numOfPsycPages--;



  //LIFO  
  #endif  
  #ifdef SCFIFO
    struct pagesInMem *pm=&proc->Ppages;
    va = PGROUNDDOWN(va);
    if(!pm->last){
      return;
    }
    int page = 0;
    for(; page < pm->last; page++){
      if(pm->container[page] == va)
        goto rearage;
    }
    return;
    rearage:
    for(;page < pm->last-1; page++)
      pm->container[page] = pm->container[page+1];
    pm->container[pm->last-1] = -1;
    pm->last--;
    proc->numOfPsycPages--;


  #endif //SCFOFO

  #ifdef LAP
    struct pagesInMem *pm=&proc->Ppages;
    va = PGROUNDDOWN(va);
    if(!pm->lapInd){
      return;
    }
    int page = 0;
    for(; page < pm->lapInd; page++){
      if(pm->container[page] == va)
        goto rearage;
    }
    return;
    rearage:
    for(;page < pm->lapInd-1; page++){
      pm->container[page] = pm->container[page+1];
      pm->accessCounter[page] = pm->accessCounter[page+1];
    }
    pm->container[pm->lapInd-1] = -1;
    pm->accessCounter[pm->lapInd-1]= 0;
    pm->lapInd--;
    proc->numOfPsycPages--;



  #endif

}

void deleteFromSwapMeta(struct proc *p,uint a){
  int i;
  for(i=0;i<MAX_PSYC_PAGES;i++){
    if(p->swapedPages.pagesOffset[i]==a){
      p->swapedPages.pagesOffset[i]=-1;
      p->swapedPages.numOfPagesInFile--;
      break;
    }
  }
  if(i>14)
    panic("removeFromsWapMeta: didn't find the file int the swap meta data\n");
}




uint removeFromPhysic(pde_t *pgdir,struct pagesInMem *pm){
  uint ret;

  #ifdef LIFO
  if(!pm->top)
      panic("(LIFO) trying to select a page while the process has none.");

  int place=pm->top-1;
  ret = pm->container[place];
  pm->container[place]=-1;       //"free" page location in array
  pm->top--;
  proc->numOfPsycPages--;


  #endif

#ifdef SCFIFO

  if(!pm->last)
      panic("(SCFIFO) trying to select a page while the process has none.");

  pte_t *pte;
  uint va=0;
  int i;
  int j;
  for(i = 0; i< MAX_PSYC_PAGES -1; i++)              
  { 
      va=pm->container[0];
       

      if((pte = walkpgdir(pgdir, (void*)va, 0)) ==0)
        panic("SCFIO remove from phys");

   
      if(*pte & PTE_A){    //acssess bit is on - give another chance
        *pte = (*pte & ~PTE_A);              //turn A bit off

        for(j=0;j<pm->last-1;j++)
          pm->container[j]=pm->container[j+1];

        pm->container[pm->last -1]=va;  
        continue;

      }
      else {    //acssess bit is off - swap thhis page
        
        pm->container[0]=-1;
    
        for(j=0;j<pm->last-1;j++)
          pm->container[j]=pm->container[j+1];
        pm->container[pm->last-1]=-1;
          
      }
      break; 
  }    
  pm->last--;
  proc->numOfPsycPages--;
  ret = va;


  #endif

  #ifdef LAP
  if(!pm->lapInd)
      panic("(LAP) trying to select a page while the process has none.");

  uint va=0;
  int findMin=pm->accessCounter[0];
  int i=0;	
  int ind=0;
  int j;
  for(i=1;i<pm->lapInd;i++){
  	if(pm->accessCounter[i]<findMin){
  		findMin=pm->accessCounter[i];
  		ind=i;	
  	}
  }

  va=pm->container[ind];
  //rintContainer(pm);
  //printAccessCounter(pm);

  if(ind<pm->lapInd-1){
  	for(j=ind;j<pm->lapInd-1;j++){
  		pm->container[j]=pm->container[j+1];
  		pm->accessCounter[j]=pm->accessCounter[j+1];
  	}
  }

  pm->container[pm->lapInd-1]=-1;
  pm->accessCounter[pm->lapInd-1]=0;
 	
  pm->lapInd--;
  proc->numOfPsycPages--;


  ret = va;  


  #endif
 
  return ret;
}



int addPage(struct pagesInMem *pm, uint va ){      //add page to container according to policy
  va=PGROUNDDOWN(va);
  
  #ifdef LIFO
  pm->container[pm->top]= va;
  pm->top++;
  proc->numOfPsycPages++;
;
  #endif

  #ifdef SCFIFO
  pm->container[pm->last] = va;
  pm->last++;
  proc->numOfPsycPages++;

  #endif


  #ifdef LAP
  pm->container[pm->lapInd] = va;
  pm->accessCounter[pm->lapInd] = 0;
  pm->lapInd++;
  proc->numOfPsycPages++;


  #endif

return 0;

}


int swapOut(uint swapedPage){           //swap 'swapedPage' out to FILE
  pte_t *pte;
  uint pa;
  char* mem;

  swapedPage=PGROUNDDOWN(swapedPage);


  if((pte=walkpgdir(proc->pgdir,(void*)swapedPage,0))==0)
    panic("Swapping Failed! trying to swap out none existing page");
  if(!(*pte & PTE_P))
    panic("SwapOut Failed! trying to SwapOut not present page");
  if(!(*pte & PTE_U))
    panic("SwapOut Failed! trying to swap out a none user page");

  pa=PTE_ADDR(*pte);   //getting the physical adress

  if(pa == 0)
    panic("kfree");

  mem=p2v(pa);

  if(!proc->hasSwapFile){
    createSwapFile(proc);
    cprintf("No SwapFile ,creating one");
  }

  //here we calculate the place to insert the page to the file
  uint offsetToWrite;
  for(offsetToWrite = 0 ; offsetToWrite<MAX_PSYC_PAGES ; offsetToWrite++){
    if(proc->swapedPages.pagesOffset[offsetToWrite]==-1){
      proc->swapedPages.pagesOffset[offsetToWrite]=swapedPage;
      proc->swapedPages.numOfPagesInFile++;
      break;
    }
  }

  if(offsetToWrite>MAX_PSYC_PAGES)
    panic("SwapOut Failed! No room in swapFile");
  

  if(writeToSwapFile(proc, (char*)swapedPage, offsetToWrite*PGSIZE,PGSIZE)<0)
     panic("SWAPOUT FAILED! failed to write to swapFile\n");

  kfree(mem);
  *pte = (*pte | PTE_PG);        //set the on file flag to 1;
  *pte &= ~PTE_P;             //set the Present falg to 0

  lcr3(v2p(proc->pgdir));   //refresh TLB
  proc->totalNumOfPagedOuts++;


  return 0;
}

int swapIn(uint page){

  uint va=PGROUNDDOWN(page);
  pte_t *pte;
  char* newAddr;

  if((pte=walkpgdir(proc->pgdir,(void*)va,0))==0){
    panic("Swap In FAILED! Trying to swap in none existing page");
    return -1;
  }
  if(*pte & PTE_P ){
    panic("Swap In FALED! Trying to swap in an existing page");
    return -1;
  }
  if(!(*pte & PTE_U)){
    panic("Swap In FAILED! Trying to swap in a none user file");
    return -1;
  }

  newAddr=kalloc();
  if(newAddr == 0){
    panic("SwapIn FAILED! no Memort to allocate");
    return -1;
  }
  memset(newAddr, 0, PGSIZE);
  
  int newFlags;
  newFlags=(PTE_FLAGS(*pte) | PTE_P) & ~PTE_PG; //turn on present flag and off PG flag
  *pte=v2p(newAddr);
  *pte=*pte | newFlags;


  //read from swap fila and copy it to the right place at the memeory
  for(int i=0;i<MAX_PSYC_PAGES;i++){
    if(proc->swapedPages.pagesOffset[i]==va){
      if(readFromSwapFile(proc,newAddr,i*PGSIZE,PGSIZE)<0)
        panic("could not read from swap File");
      proc->swapedPages.pagesOffset[i]=-1;
      proc->swapedPages.numOfPagesInFile--;
     }
  }

  addPage(&proc->Ppages,va);
  return 1;
  
}

int handlePageFoult(uint va){
  pte_t *pte;
  pde_t *pde = proc->pgdir;

  // cprintf("Page Fault!!!!\n");
  if((pte = walkpgdir(pde,(void*)va,0))==0){
    panic("error at handlePageFoult: pte =0\n");
    return -1;}

  if(*pte & PTE_P){
    panic("at handlePageFoult: page is present!\n");
    return -1;}

  if(!(*pte & PTE_PG)){
    panic("at handlePageFoult: page is not at file!\n");
    return -1;}

  if(!(*pte & PTE_U)){
    panic("at handlePageFoult: NOT USER ACCESS!\n");
    return -1;}


    if(proc->numOfPsycPages==15){
      uint swapi = removeFromPhysic(proc->pgdir,&proc->Ppages);
      swapOut(swapi);
    }

    return swapIn(va);
    
  }

void
  copyPm(struct pagesInMem* pm, struct pagesInMem* copyPm)
  { 
    #ifdef LIFO
    for(int i = 0; i < MAX_PSYC_PAGES; i++)
      copyPm->container[i] = pm->container[i];
    copyPm->top = pm->top;
    #endif 

    #ifdef SCFIFO
    for(int i = 0; i < MAX_PSYC_PAGES; i++)
      copyPm->container[i] = pm->container[i];
    copyPm->last = pm->last;
    #endif 

    #ifdef LAP
    for(int i = 0; i < MAX_PSYC_PAGES; i++){
       copyPm->container[i] = pm->container[i];
  	   copyPm->accessCounter[i] = pm->accessCounter[i];}
    copyPm->lapInd = pm->lapInd;
    #endif 

}
void
  clearPm(struct pagesInMem* pm)
  {
    #ifdef LIFO
    for(int i = 0; i < MAX_PSYC_PAGES; i++)
      pm->container[i] = -1;
    pm->top = 0;
    #endif

    #ifdef SCFIFO
    for(int i = 0; i < MAX_PSYC_PAGES; i++)
      pm->container[i] = -1;
    pm->last = 0;
    #endif

    #ifdef LAP
    for(int i = 0; i < MAX_PSYC_PAGES; i++){
      pm->container[i] = -1;
  	  pm->accessCounter[i] = 0;}
    pm->lapInd = 0;
    #endif
}

void clearSwapData(struct swapedMetaData *sm){
  for(int i=0; i< MAX_PSYC_PAGES; i++)
    sm->pagesOffset[i] = -1;
  sm->numOfPagesInFile = 0;
  
}  

int checkShellInit(char nm[]){
  if(nm[0]== 's' && nm[1]=='h')
    return 0;  
  if(nm[0]=='i' && nm[1]== 'n' && nm[2]=='i' && nm[3]=='t')
    return 0;

  return 1;
}



void printContainer(struct pagesInMem* pm){

for (int i = 0; i <MAX_PSYC_PAGES ; ++i)
  cprintf("container [%d] : = %d\n",i,pm->container[i]);
}
#ifdef LAP
void printAccessCounter(struct pagesInMem* pm){

for (int i = 0; i <MAX_PSYC_PAGES ; ++i)
  cprintf("accessCounter [%d] : = %d\n",i,pm->accessCounter[i]);
}


void updateAccessed(){             //last function in this mother fu**ing ASS face assignment
	pte_t *pte;

	/*if( !(checkShellInit(proc->name)) || !proc )
		return;*/
	if(!proc || proc->pid <= 2)
		return;

	 for(int page=0;page<MAX_PSYC_PAGES; page++){
      if((proc->Ppages).accessCounter[page] < 4294967295 ){
        pte = walkpgdir(proc->pgdir, (char*)(page*PGSIZE), 0);
        if(*pte & PTE_A)
          (proc->Ppages).accessCounter[page]++;
        *pte = *pte & ~PTE_A;
        lcr3(v2p(proc->pgdir)); // refresh TLB
        }
    }
    
    //printAccessCounter(&proc->Ppages);
   
}	
#endif	




#endif