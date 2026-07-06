/*
 *========== PROCESS MEMORY AUDITOR ==========
 * 
 * SPDX-License-Identifier: MIT
 * 
 * proc_mem_audit.c
 * Linux process memory mapping audit tool.
 *
 * This tool takes in the Process ID (pid) of interest, looks at the maps and status
 * and determines whether the process is currently in a suspicious runtime state.
 * ---------------------------------------------------------------------------------
 * ---------- Copyright (c) 2026 William ----------
 * ---------------------------------------------------------------------------------
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdbool.h>  
 #include <stdint.h>     //uint64_t 
 #include <errno.h>      //errno 
 #include <ctype.h>      //isspace
 #include <unistd.h>     //pid_t
 #include <sys/types.h>  //pid_t
 #include <limits.h>     //PATH_MAX

 #define MAX_MAPS 1024
 #define MAX_LINE 1024
 #define MAX_PERMS 8
 #define MAX_DEV 32
 #define MAX_PATH 512

 //---------------------------------------------------------------------------------

 //---------- DATA STRUCTURES ----------
 //-------------------------------------
 //---Process Status---
 //This stores important fields from /proc/<pid>/status
 typedef struct {
    pid_t pid;
    char name[128];
    char state[64];

    int ppid;
    int tracer_pid;

    unsigned long vm_size_kb;
    unsigned long vm_rss_kb;
    unsigned long vm_data_kb;
    unsigned long vm_stk_kb;
    unsigned long vm_exe_kb;
    unsigned long vm_lib_kb;

    int threads;
 } proc_status_t;
//--------------------------------------

//---Memory Mapping---
//This stores important fields from /proc/<pid>/maps
typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t size;

    char perms[MAX_PERMS]; //e.g. "r-xp", "rwxp" etc.
    uint64_t offset;

    char dev[MAX_DEV];     //e.g "103:02"
    unsigned long inode;

    char path[MAX_PATH];   // file path, [stack], [vdso], or empty
} map_entry_t;
//--------------------------------------

//---Full Process Map---
typedef struct {
    map_entry_t entries[MAX_MAPS];
    size_t count;
} map_list_t;
//--------------------------------------

//---Audit Result Summary---
//To be used to print a summary at the end of the audit.
typedef struct {
    int total_mappings;
    int executable_mappings;
    int wx_mappings;
    int suspicious_nf_executable_mappings;
    int executable_stack;
    int executable_heap;
    int suspicious_rule_hits;
    int suspicious_mapping_count;
} audit_summary_t;
//----------------------------------------------------------------------------------

//---------- FUNCTIONS ----------
//-------------------------------
//---Parse Command-Line PID---
//This takes the pid of the process of interest as an argument from CLI.
int parse_pid(const char *arg, pid_t *pid_out){
    char *endptr = NULL;
    errno = 0;

    long value = strtol(arg, &endptr, 10);
    
    if(errno != 0){
        return -1;
    }

    if(endptr == arg){
        return -1; //no digits parsed
    }

    if(*endptr != '\0'){
        return -1; //non-numeric characters found
    }

    if(value <= 0){
        return -1; //invalid PID
    }

    *pid_out = (pid_t)value;
    return 0;
}
//-------------------------------

//---Build /proc Path---
//This builds paths like /proc/<pid>/maps etc
int build_proc_path(pid_t pid, const char *file, char *out, size_t out_len){
    if(file == NULL || out == NULL || out_len == 0){
        return -1;
    }

    int written = snprintf(out, out_len, "/proc/%d/%s", pid, file);

    if(written < 0){
        return -1;
    }

    if((size_t)written >- out_len){
        return -1; //output truncated
    }

    return 0;
}
//-------------------------------

//---Read Process Status---
//Open and parse /proc/<pid>/status
int read_proc_status(pid_t pid, proc_status_t *status){
    char path[256];
    char line[MAX_LINE];

    if(status == NULL){
        return -1;
    }

    memset(status, 0, sizeof(*status));

    if(build_proc_path(pid, "status", path, sizeof(path)) != 0){
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if(fp == NULL){
        perror("fopen status");
        return -1;
    }

    while(fgets(line, sizeof(line), fp) != NULL){
        if(strncmp(line, "Name:", 5) == 0){
            sscanf(line, "Name: %127s", status->name);
        }
        else if(strncmp(line, "State:", 6) == 0){
            sscanf(line, "State: %63[^\n]", status->state);
        }
        else if(strncmp(line, "Pid:", 4) == 0){
            sscanf(line, "Pid: %d", &status->pid);
        }
        else if(strncmp(line, "PPid:", 5) ==0){
            sscanf(line, "PPid: %d", &status->ppid);
        }
        else if(strncmp(line, "TracerPid:", 10) ==0){
            sscanf(line, "TracerPid: %d", &status->tracer_pid);
        }
        else if(strncmp(line, "VmSize:", 7) == 0){
            sscanf(line, "VmSize: %lu kB", &status->vm_size_kb);
        }
        else if(strncmp(line, "VmRSS:", 6) == 0){
            sscanf(line, "VmRSS: %lu kB", &status->vm_rss_kb);
        }
        else if(strncmp(line, "VmData:", 7) == 0){
            sscanf(line, "VmData: %lu kB", &status->vm_data_kb);
        }
        else if(strncmp(line, "VmStk:", 6) == 0){
            sscanf(line, "VmStk: %lu kB", &status->vm_stk_kb);
        }
        else if(strncmp(line, "VmExe:", 6) == 0){
            sscanf(line, "VmExe: %lu kB", &status->vm_exe_kb);
        }
        else if(strncmp(line, "VmLib:", 6) == 0){
            sscanf(line, "VmLib: %lu kB", &status->vm_lib_kb);
        }
        else if(strncmp(line, "Threads:", 8) == 0){
            sscanf(line, "Threads: %d", &status->threads);
        }
    }

    fclose(fp);
    return 0;
}
//-------------------------------

//---Parse One /proc/<pid>/maps Line---
//Converts one maps line into a map_entry_t
int parse_map_line(const char *line, map_entry_t *entry){
    unsigned long start = 0;
    unsigned long end = 0;
    unsigned long offset = 0;
    unsigned long inode = 0;

    char perms[MAX_PERMS] = "";
    char dev[MAX_DEV] = "";
    char path[MAX_PATH] = "";

    if(line == NULL || entry == NULL){
        return -1;
    }

    memset(entry, 0, sizeof(*entry));

    int n = sscanf(
        line, 
        "%lx-%lx %7s %lx %31s %lu %511[^\n]",
        &start,
        &end,
        perms,
        &offset,
        dev,
        &inode,
        path
    );

    if(n<6){
        return -1;
    }

    if(end <= start){
        return -1;
    }

    entry->start = start;
    entry->end = end;
    entry->size = end-start;
    entry->offset = offset;
    entry->inode = inode;

    strncpy(entry->perms, perms, sizeof(entry->perms) - 1);
    strncpy(entry->dev, dev, sizeof(entry->dev) - 1);

    if(n==7){
        strncpy(entry->path, path, sizeof(entry->path) - 1);
    }
    else{
        entry->path[0] = '\0';
    } 

    return 0;
}
//-------------------------------

//---Read All Mappings---
//Opens maps, reads each line and calls the parser.
int read_proc_maps(pid_t pid, map_list_t *maps){
    char path[256];
    char line[MAX_LINE];

    if(maps == NULL){
        return -1;
    }

    memset(maps, 0, sizeof(*maps));
    
    if(build_proc_path(pid, "maps", path, sizeof(path)) != 0){
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if(fp == NULL){
        perror("fopen maps");
        return -1;
    }

    while(fgets(line, sizeof(line), fp) != NULL){
        if(maps->count >= MAX_MAPS){
            fprintf(stderr, "Too many mappings; increase MAX_MAPS\n");
            fclose(fp);
            return -1;
        }

        map_entry_t entry;

        if(parse_map_line(line, &entry) == 0){
            maps->entries[maps->count] = entry;
            maps->count++;
        }
    }

    fclose(fp);
    return 0;
}
//-------------------------------

//___Classification Functions___
//---Is Executable?---
bool map_is_executable(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    return strchr(m->perms, 'x') != NULL;
}
//-------------------------------

//---Is Writable?---
bool map_is_writable(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    return strchr(m->perms, 'w') != NULL;
}
//-------------------------------

//---Is WX?---
bool map_is_wx(const map_entry_t *m){
    return map_is_writable(m) && map_is_executable(m);
}
//-------------------------------

//---Is File-Backed?---
bool map_is_file_backed(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    return m->path[0] == '/';
}
//-------------------------------

//---Is Special Kernel Mapping?---
//To avoid flagging normal special mappings.
bool map_is_special_allowed(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    return strcmp(m->path, "[vdso]") == 0 ||
           strcmp(m->path, "[vsyscall]") == 0;
}
//-------------------------------

//---Is Anonymous?---
//Detects mappings not backed by a normal file.
bool map_is_anonymous(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    return m->path[0] == '\0';
}
//-------------------------------

//---Is Stack?---
bool map_is_stack(const map_entry_t *m){
    if(m == NULL){
        return false;
    }

    return strstr(m->path, "[stack") != NULL;
}
//-------------------------------

//---Is Heap?---
bool map_is_heap(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    return strcmp(m->path, "[heap]") == 0;
}
//-------------------------------

//---Is Non-File Executable Suspicious?---
bool map_is_suspicious_nonfile_exec(const map_entry_t *m){
    if(m == NULL){
        return false;
    }
    if(!map_is_executable(m)){
        return false;
    }
    if(map_is_file_backed(m)){
        return false;
    }
    if(map_is_special_allowed(m)){
        return false;
    }
    return true;
}
//-------------------------------

//___Analysis Functions____
//---Analyse Mappings---
//Loops every mapping and counts types of mappings
void analyse_maps(const map_list_t *maps, audit_summary_t *summary){
    if(maps == NULL || summary == NULL){
        return;
    }

    memset(summary, 0, sizeof(*summary));

    summary->total_mappings = (int)maps->count;

    for(size_t i = 0; i < maps->count; i++){
        const map_entry_t *m = &maps->entries[i];
        bool suspicious = false;

        if(map_is_executable(m)){
            summary->executable_mappings++;
        }
        if(map_is_writable(m) && map_is_executable(m)){
            summary->wx_mappings++;
            summary->suspicious_rule_hits++;
            suspicious = true;
        }
        if(map_is_suspicious_nonfile_exec(m)){
            summary->suspicious_nf_executable_mappings++;
            summary->suspicious_rule_hits++;
            suspicious = true;
        }
        if(map_is_stack(m) && map_is_executable(m)){
            summary->executable_stack++;
            summary->suspicious_rule_hits++;
            suspicious = true;
        }
        if(map_is_heap(m) && map_is_executable(m)){
            summary->executable_heap++;
            summary->suspicious_rule_hits++;
            suspicious = true;
        }

        if(suspicious){
            summary->suspicious_mapping_count++;
        }
    }
}
//-------------------------------

//---Print Process Status---
void print_proc_status(const proc_status_t *status){
    if(status == NULL){
        return;
    }

    printf("=== Process Status ===\n");
    printf("PID:       %d\n", status->pid);
    printf("Name:      %s\n", status->name);
    printf("State:     %s\n", status->state);
    printf("PPid:      %d\n", status->ppid);
    printf("TracerPid: %d\n", status->tracer_pid);
    printf("Threads:   %d\n", status->threads);

    printf("\n=== Memory Status ===\n");
    printf("VmSize: %lu kB\n", status->vm_size_kb);
    printf("VmRSS:  %lu kB\n", status->vm_rss_kb);
    printf("VmData: %lu kB\n", status->vm_data_kb);
    printf("VmStk:  %lu kB\n", status->vm_stk_kb);
    printf("VmExe:  %lu kB\n", status->vm_exe_kb);
    printf("VmLib:  %lu kB\n", status->vm_lib_kb);
}
//-------------------------------

//---Print Executable Mappings---
//Prints all mappings with x permission.
void print_executable_mappings(const map_list_t *maps){
    if(maps == NULL){
        return;
    }

    printf("\n=== Executable Mappings===\n");
    for(size_t i = 0; i < maps->count; i++){
        const map_entry_t *m = &maps->entries[i];
        
        if(map_is_executable(m)){
            printf("%lx-%lx %s %lx %s %lu %s\n",
                (unsigned long)m->start,
                (unsigned long)m->end,
                m->perms,
                (unsigned long)m->offset,
                m->dev,
                m->inode, m->path);
        }
    }
}
//-------------------------------

//---Print WX Mappings---
void print_wx_mappings(const map_list_t *maps){
    if(maps == NULL){
        return;
    }

    printf("\n=== Writable AND Executable Mappings ===\n");
    for(size_t i = 0; i < maps->count; i++){
        const map_entry_t *m = &maps->entries[i];
        
        if(map_is_wx(m)){
            printf("%lx-%lx %s %lx %s %lu %s\n",
                (unsigned long)m->start,
                (unsigned long)m->end,
                m->perms,
                (unsigned long)m->offset,
                m->dev,
                m->inode, m->path);
        }
    }
}
//-------------------------------

//---Print Non-File Executable Mappings---
//Prints executable mappings that are not normal file-backed code and not [vdso]/[vsyscall]
void print_nf_exec_mappings(const map_list_t *maps){
    if(maps == NULL){
        return;
    }

    printf("\n=== Suspicious Non-File Executable Mappings ===\n");
    for(size_t i = 0; i < maps->count; i++){
        const map_entry_t *m = &maps->entries[i];
        
        if(!map_is_executable(m)){
            continue;
        }

        bool print = false;

        if(map_is_anonymous(m)){
            printf("[Anonymous] ");
            print = true;
        }
        if(map_is_suspicious_nonfile_exec(m)){
            printf("[Non-File] ");
            print = true;
        }
        
        if(print){
            printf("%lx-%lx %s %lx %s %lu %s\n",
                (unsigned long)m->start,
                (unsigned long)m->end,
                m->perms,
                (unsigned long)m->offset,
                m->dev,
                m->inode, m->path);
        }
    }
}
//-------------------------------

//---Print Risk Summary---
void print_risk_summary(const proc_status_t *status, const audit_summary_t *summary){
    if(status == NULL || summary == NULL){
        return;
    }

    printf("\n=== Risk Summary ===\n");

    printf("Total Mappings: %d\n", summary->total_mappings);
    printf("Executable Mappings: %d\n", summary->executable_mappings);
    printf("WX Mappings: %d\n", summary->wx_mappings);
    printf("Non-File Executable Mappings: %d\n", summary->suspicious_nf_executable_mappings);
    printf("Suspicious Mapping Count: %d\n", summary->suspicious_mapping_count);
    printf("Suspiciouis Rule Hits: %d\n", summary->suspicious_rule_hits);

    printf("\nFindings:\n");

    if(status->tracer_pid != 0){
        printf("[HIGH] Process is currently being traced by PID %d\n", status->tracer_pid);
    }
    if(summary->wx_mappings > 0){
        printf("[CRITICAL] Writable AND executable mappings present\n");
    }
    if(summary->executable_stack){
        printf("[CRITICAL] Executable stack present\n");
    }
    if(summary->executable_heap){
        printf("[CRITICAL] Executable heap present\n");
    }
    if(summary->suspicious_nf_executable_mappings > 0){
        printf("[HIGH] Non-file executable mappings present\n");
    }

    if(status->tracer_pid == 0 &&
        summary->wx_mappings == 0 &&
        summary->executable_stack == 0 &&
        summary->executable_heap == 0 &&
        summary->suspicious_nf_executable_mappings == 0){
            printf("[OKAY] No obvious memory-execution risks detected\n");
        }
    
}
//-------------------------------

//___ASLR-Compatible Design Function___
//---Build Normalised Mapping Key---
//Creates a string that represents a mapping WITHOUT using its absolute virtual address.
void build_normalised_key(const map_entry_t *m, char *out, size_t out_len);
//-------------------------------


int main(int argc, char **argv){

    pid_t pid;
    proc_status_t status;
    map_list_t maps;
    audit_summary_t summary;

    if(argc != 2){
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    if(parse_pid(argv[1],  &pid) != 0){
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    if(read_proc_status(pid, &status) != 0){
        fprintf(stderr, "Failed to read /proc/%d/status\n", pid);
        return 1;
    }

    if(read_proc_maps(pid, &maps) != 0){
        fprintf(stderr, "Failed to read /procs/%d/maps\n", pid);
        return 1;
    }

    analyse_maps(&maps, &summary);

    printf("\n===== Process Memory Audit =====\n");

    print_proc_status(&status);
    print_executable_mappings(&maps);
    print_wx_mappings(&maps);
    print_nf_exec_mappings(&maps);
    print_risk_summary(&status, &summary);

    return 0;
}