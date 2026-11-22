// Created by 0xdhanesh
// 22.11.2026
// STL = Standard Template Library 
#include <map> // C++ STL: Key-value store - Stores elements as pairs with unique keys
#include <set> // C++ STL: Unique collection - Duplicate values are ignored automatically
#include <bsm/audit.h> // bsm - Basic Security Module for macOS/Darwin; Provides System calls & constants: Declares auditing system calls (such as audit(), auditctl(), auditon(), getaudit(), setaudit(), getauid(), and setauid())
#include <pthread.h> // POSIX threads - multi thread operations
#include <dispatch/dispatch.h> // GCD (Grand Central Dispatch) — async task queuing, likely for processing audit events off the main thread

// C++ linkage specification that tells the compiler to use C-style naming and calling conventions for functions and variables
extern "C" {
    #include <libproc.h> // Apple private/public API: process information — proc_pidinfo(), proc_name(), etc.
    #include <sys/proc_info.h> // Companion header: structs for process info queries (proc_bsdinfo, proc_taskinfo, etc.)

    #include <libren/libren.h> // renamed from libjailbreak
    #include "common.h"  // Local shared definitions

    // Private Apple API (not in public SDK)
    // Takes an audit_token (kernel-issued process identity token) and returns pidversion
    // pidversion = PID + version counter — uniquely identifies a process instance even if PID is reused
    // Used to prevent PID-reuse attacks when tracking processes via audit events
    extern int audit_token_to_pidversion(audit_token_t atoken);

}

// Tracks processes that must be hidden/suppressed WITHOUT using the cache (live kernel queries each time)
// set<pid_t*> = unique collection of PID pointers — processes flagged as blacklisted
/* NOTE:
static  std::set < pid_t   * >*   uncachedBlacklistedProcesses
  │          │        │    │  │
  │          │        │    │  └─ outer * → the VARIABLE is a pointer (points to a set on the heap)
  │          │        │    └─ inner * → the SET CONTAINS pointers-to-pid_t, not pid_t values directly
  │          │        └─ pid_t → typedef for int (process ID type) [builtin]
  │          └─ std::set<> → unique sorted collection [builtin]
  └─ static → file-scoped global lifetime 
Reading C++ types right-to-left (the standard rule):
Start at the variable name: uncachedBlacklistedProcesses
Move right → hit * → "is a pointer to..."
Move left → hit std::set<pid_t*> → "...a set of pid_t pointers"
*/
// uncachedBlacklistedProcesses is a pointer to a set of pointers-to-pid_t
static std::set<pid_t*>* uncachedBlacklistedProcesses;
// blacklistedProcessesState is a pointer to a map of pid_t → int (process state)
static std::map<pid_t, int>* blacklistedProcessesState;

// C++ global initialiser — called by runtime at load time before main() runs (__mod_init_func / __attribute__((constructor)))
static void cxx_global_vars_init(){
    // Allocates the live-verification blacklist set on heap
    /* 
    NOTE:
    In C++:
    | Syntax	                | Where allocated
    | std::set<pid_t*> s;	    | Stack — freed automatically when the function returns
    | new std::set<pid_t*>()	| Heap — lives until explicitly deleted
    */
   /*
    NOTE: 
    uncachedBlacklistedProcesses = new std::set<pid_t*>();
        │                           │
        │                           └─ new → heap allocation, returns pointer to a freshly constructed std::set [builtin]
        │                                       () → default constructor: empty set, no elements
        └─ uncachedBlacklistedProcesses → global pointer (declared outside) now points to this heap object

    Reading: "assign to uncachedBlacklistedProcesses a new heap-allocated empty set of pid_t pointers"
    */
    uncachedBlacklistedProcesses = new std::set<pid_t*>();
    /* NOTE:
    blacklistedProcessesState = new std::map<pid_t, int>();
        │                        │
        │                        └─ new → heap allocation, returns pointer to a freshly constructed std::map [builtin]
        │                                     () → default constructor: empty map, no key-value entries
        └─ blacklistedProcessesState → global pointer (declared outside) now points to this heap object

    Reading: "assign to blacklistedProcessesState a new heap-allocated empty map of pid_t → int"
    */
    blacklistedProcessesState = new std::map<pid_t, int>();
}

// Thread synchronisation lock protecting concurrent access to blacklistedProcessesState and uncachedBlacklistedProcesses
// pthread_rwlock_t allows: multiple simultaneous READers OR one exclusive WRITEer — never both at once [builtin]
static pthread_rwlock_t stateLock = {0};

/* NOTE:
Lock Lifecycle: 
stateLockInit()      → lock ready
stateReadLock()      → shared read access (many at once OK)
stateReadUnlock()    → release read
stateWriteLock()     → exclusive write access (blocks all others)
stateWriteUnlock()   → release write
*/


// Initialises stateLock — must be called once before any read/write lock calls
static void stateLockInit()
{
    pthread_rwlock_init(&stateLock, NULL);
}

// Acquires a SHARED read lock — multiple threads can hold this simultaneously
static void stateReadLock()
{
    pthread_rwlock_rdlock(&stateLock);
}

// Releases a previously acquired read lock [builtin]
static void stateReadUnlock()
{
    pthread_rwlock_unlock(&stateLock);
}

// Acquires an EXCLUSIVE write lock — no other reader or writer may proceed
static void stateWriteLock()
{
    pthread_rwlock_wrlock(&stateLock);
}

// Releases a previously acquired write lock [builtin]
static void stateWriteUnlock()
{
    pthread_rwlock_unlock(&stateLock);
}

// Master initialiser for process-supression 
static void initBlacklistState()
{
    // builtin function dispatch_once_t: opaque token that tracks if a block has run
    // static facilitates the usage of same token multiple times
    static dispatch_once_t onceToken;

    // dispatch_once executes the block EXACTLY_ONCE for the lifetime of process
    dispatch_once(&onceToken, ^{
        stateLockInit();  // Initialise the pthread rwlock (must happen before any lock calls)
        cxx_global_vars_init(); // Heap-allocate the blacklist set and state map
    });

    /* FLOW:
    initBlacklistState()         ← called once at startup
        └─ stateLockInit()         ← rwlock ready
        └─ cxx_global_vars_init()  ← blacklist set + state map on heap
                ↓
            [audit event loop starts, using stateReadLock/stateWriteLock to protect map/set access] 
    */
}
