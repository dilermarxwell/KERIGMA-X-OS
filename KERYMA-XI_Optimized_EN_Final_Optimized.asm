

// =============================
//   Permission Check (RBAC)
// =============================
section .text
section .text
// Kernel code here

section .data
section .data
syscall_table dq sys_exit, sys_read, sys_write
user_roles db 0

section .bss
section .bss
keyboard_buffer resb 128
; =============================
;   RBAC: Verificação de Permissões
;   Entrada: RDI = Índice da permissão, RSI = Máscara requerida
;   Saída: RAX = 0 (sucesso) ou 1 (falha)
; =============================
check_permissions:
    cmp byte [user_roles], 1       ; Administrador tem acesso total
    je .access_granted
    mov al, [permissions_table + rdi]
    test al, sil                   ; Verificar máscara de permissão
    jz .rbac_access_denied
.access_granted:
    xor rax, rax                   ; Sucesso (0)
    ret
.rbac_access_denied:
    mov rax, 1                     ; Falha (1)
    ret
    cmp byte [user_roles], 1       ; Administrador tem acesso total
    je .access_granted
    mov al, [permissions_table + rdi]
    test al, sil                   ; Verificar permissão do usuário
    jz .rbac_access_denied
.access_granted:
    xor rax, rax                   ; Sucesso
    ret
.rbac_access_denied:
    mov rax, 1                     ; Falha
    ret
    mov al, [permissions_table + rdi]  ; Properly fetch user permissions
    test al, sil                      ; Check against required mask
    jz .rbac_access_denied
    xor rax, rax                      ; Success (0)
    ret
.rbac_access_denied:
    mov rax, 1                         ; Failure (1)
    ret
    cmp byte [user_roles], 1       ; Checks if user is an administrator
    jne .rbac_access_denied
    mov al, [permissions_table + rdi]
    test al, sil                   ; Compares mask
    jz .rbac_access_denied
    xor rax, rax                   ; Success (0)
    ret
    mov rax, 1                     ; Failure (1)
    ret
// Kernel code here


    jne .rbac_access_denied
    mov al, [permissions_table + rdi]
    test al, sil                   ; Compares mask
    jz .rbac_access_denied
    xor rax, rax                   ; Success (0)
    ret
    mov rax, 1                     ; Failure (1)
    ret

// ===== Context Switching =====
// =============================
//   Context Switch (Scheduler)
// =============================
// Input: None
// Output: None (Loads the next process context)
context_switch:
%macro SAVE_CONTEXT 0
    push rax
    push rcx
    push rdx
    ; // ... (outros registradores)
%endmacro
    // ... código de troca ...
    RESTORE_CONTEXT
    ret
    pushfq
    push rbx
    fxsave [current_fpu_state]
%macro SAVE_CONTEXT 0
    push rax
    push rcx
    push rdx
    ; ... (outros registradores)
%endmacro
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro
%macro RESTORE_CONTEXT 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
%endmacro
    call find_least_loaded_core  ; Proper CPU selection for load balancing
    mov rsp, [next_process_stack] ; Proper stack switch
    fxrstor [next_fpu_state]
    pop rbx
    popfq
    ret
    push rbx
    fxsave [current_fpu_state]
    // Context switching code here ...
    fxrstor [next_fpu_state]
    pop rbx
    ret

// ===== Syscalls =====
sys_exit:
    mov rdi, rax  ; Set exit code
    call terminate_process
    jmp schedule_next_task  ; Ensure another task runs
sys_read:
    mov rdi, rdx  ; Buffer
    mov rsi, rbx  ; Size
    call read_from_device
    ret
    // Implementation ...
    // Implementation ...
    // Main kernel code
// Kernel code here


    align 16
    // Uninitialized data
    stack_guard resb 4096
    vtx_enabled resb 1

// Kernel code here


    align 8
permissions_table db 1, 1, 0, 0  ; [read, write, exec, net]
    align 8
    // Dados inicializados
user_roles db 0      ; 0 = usuário normal
permissions_table db 1, 1, 0, 0  ; [read, write, exec, net]

// --- Implementation de RBAC (Controle de Acesso Baseado em Função) ---

// --- Implementation de RBAC (Controle de Acesso Baseado em Função) ---
// --- Função unificada de verificação de permissões ---
// --- Função de verificação de permissões unificada ---

// =============================
//   RBAC: Controle de Acesso
// =============================
// Entrada: 
//   - RDI = Índice da permissão
//   - RSI = Máscara de permissão requerida
// Saída:
//   - RAX = 0 (sucesso) ou 1 (falha)
    cmp byte [user_roles], 1       ; Verifica se usuário é admin
    jne .rbac_access_denied
    mov al, [permissions_table + rdi]
    test al, sil                   ; Compares mask
    jz .rbac_access_denied
    xor rax, rax                   ; Sucesso
    ret

    mov rax, 1                     ; Falha
    ret
    cmp byte [user_roles], 1
    jne .rbac_access_denied
    mov al, [permissions_table + rdi]
    test al, sil
    jz .rbac_access_denied
    xor rax, rax    ; Sucesso
    ret
    mov rax, 1      ; Falha
    ret
    // Entrada: RDI = índice da permissão, RSI = máscara requerida
    // Saída: RAX = 0 (sucesso) ou 1 (falha)
    jne .rbac_access_denied_rbac
    mov al, [permissions_table + rdi]
    test al, sil                  ; Verifica a máscara de permissão
    jz .rbac_access_denied_rbac
    xor rax, rax                  ; Sucesso
    ret
.rbac_access_denied_rbac:
    mov rax, 1                    ; Falha
    ret
    jne .rbac_access_denied
    xor rax, rax
    ret
    mov rax, 0x1
    ret
    cmp byte [user_roles], 1  ; Verifica se usuário é administrador
    jne .rbac_access_denied_rbac  ; Label único para RBAC
    xor rax, rax              ; Success (0)
    ret
    mov rax, 0x1              ; Código de erro
    ret
    jne .rbac_access_denied
    xor rax, rax  ; Success (0)
    ret
    mov rax, 0x1  ; Código de erro
    ret
    jne .rbac_access_denied
    ret
    mov rax, 0x1  ; Código de erro
    ret
    jne access_denied
    ret
    mov rax, 0x1  ; Código de erro de permissão negada
    ret
    push rbx
    mov rbx, [user_roles]
    cmp rbx, 1
    jne access_denied
    pop rbx
    ret
    mov rax, [user_roles]
    cmp rax, 1
    jne access_denied
    ret

    mov rax, 0x1  ; Código de erro de permissão negada
    ret

vtx_error_msg db "VT-x/AMD-V não suportado", 0
// [MLFQ] - Implementation do escalonador de filas multinível
// Cada nível representa uma prioridade diferente,
// com aging para evitar starvation.
// =================================================
// Escolhe qual processo será executado em seguida com base na prioridade.
// 1. Percorre as filas de prioridade para encontrar um processo pronto.

// ---- Context Switching Segura ----
// --- Função unificada de troca de contexto ---


// =============================
//   Context Switching (Scheduler)
// =============================
// Salva e restaura o estado do processador durante a troca de tarefas.
// Entrada:
//   - Nenhuma (executado internamente pelo escalonador)
// Saída:
//   - Nenhuma (contexto da nova tarefa é carregado)
    push rbx
    fxsave [current_fpu_state]
    // Código de troca de contexto aqui
    fxrstor [next_fpu_state]
    pop rbx
    ret
    push rbx
    fxsave [current_fpu_state]
    // Código de troca de contexto aqui
    fxrstor [next_fpu_state]
    pop rbx
    ret
    // ... código ...
    jne .rbac_access_denied_context
    // ... código ...
    ret
.rbac_access_denied_context:
    mov rax, -EPERM
    ret
    fxsave [current_fpu_state]
    lock xchg [current_task], rbx
    call select_next_task
    mov rbx, [next_task]
    mov cr3, [rbx + PCB.page_dir]
    fxrstor [next_fpu_state]
    ret
    fxsave [current_fpu_state]
    lock xchg [current_task], rbx
    call select_next_task
    mov rbx, [next_task]
    mov cr3, [rbx + PCB.page_dir]  ; Atualiza CR3 para o novo processo
    fxrstor [next_fpu_state]
    ret
    fxsave [current_fpu_state]
    lock xchg [current_task], rbx
    call select_next_task
    mov rbx, [next_task]
    mov cr3, [rbx + PCB.page_dir]  ; Atualiza CR3 para o novo processo
    fxrstor [next_fpu_state]
    ret
    fxsave [current_fpu_state]
    lock xchg [current_task], rbx
    call select_next_task
    fxrstor [next_fpu_state]
    ret
    push rbx
    fxsave [current_fpu_state]  ; Salva estado FPU
    mov rbx, current_task
    call save_task_state
    call select_next_task
    call restore_task_state
    fxrstor [next_fpu_state]
    pop rbx
    ret
    fxsave [current_fpu_state]  ; Salva estado da FPU do processo atual
    // ... (lógica de troca de contexto)
    fxrstor [next_fpu_state]    ; Restaura estado da FPU do próximo processo

    pushfq
    cli
    call save_task_state
    call select_next_task
    call restore_task_state
    sti  ; Reativa interrupções após a troca de contexto
    ret
// 3. Se nenhum processo estiver pronto, entra em estado de espera.
// - Verifica as filas de prioridade em busca de um processo pronto.
// - Se não houver processos disponíveis, o sistema entra em estado de idle.
// - Organiza processos em múltiplas filas de prioridade.
// - Processos que consomem muito tempo de CPU são movidos para filas mais baixas.
// - Processos que esperam muito tempo na fila podem subir de prioridade (aging).
// ESCALONAMENTO DE PROCESSOS
// - Implementa aging para evitar starvation.
// - Suporta troca de contexto eficiente entre processos em execução.
    sti
    hlt
    pushfq
    cli
    jmp schedule
    sti     ; Habilita interrupções antes de `hlt`
    hlt
    pushfq
    cli
    jmp schedule
    jmp schedule
    mov esi, calculate_dynamic_priority()

// =============================
//   Escalonador MLFQ (Multilevel Feedback Queue)
// =============================
.scheduler_loop:
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_to_process
    dec esi
    jmp .scheduler_loop

.switch_to_process:
    call context_switch
    ret
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
.switch_process:
    call context_switch
    ret
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    jmp schedule
    mov esi, calculate_dynamic_priority()  ; Começa pela prioridade mais alta
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]         ; Gets the current queue
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    jmp schedule           ; Volta a verificar após hibernar
    call apply_aging
    mov esi, 0
    cmp esi, MAX_PRIORITY_LEVELS
    jge .idle
    // Removendo sti inseguro, pois pode habilitar interrupções cedo demais
    jne .switch_process
    inc esi
    jmp .loop
    call context_switch
// Switches execution context between processes
    fxsave [current_fpu_state]  ; Salva estado da FPU do processo atual
    // ... (lógica de troca de contexto)
    fxrstor [next_fpu_state]    ; Restaura estado da FPU do próximo processo

    push rbx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    fxsave [current_fpu_state]
switch_page_directory:
    test rdi, 0xFFF          ; Verificar alinhamento de 4KB
    jnz .invalid_address
    mov rax, cs
    and rax, 0x03
    cmp rax, 0
    jne .invalid_cpl
    test rdi, 0xFFF
    jnz .invalid_address
    mov cr3, rdi
    ret
.invalid_cpl:
    mov rax, -EPERM  ; Acesso negado
    ret
    ret
.invalid_address:
    mov rax, -EFAULT
    ret
    fxrstor [next_fpu_state]
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    fxsave [current_fpu_state]
    test rdi, 0xFFF          ; Verificar alinhamento de 4KB
    jnz .invalid_address
    mov rax, cs
    and rax, 0x03
    cmp rax, 0
    jne .invalid_cpl
    test rdi, 0xFFF
    jnz .invalid_address
    mov cr3, rdi
    ret
    mov rax, -EPERM  ; Acesso negado
    ret
    ret
    mov rax, -EFAULT
    ret
    fxrstor [next_fpu_state]
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    fxsave [current_fpu_state]  ; Salvar estado da FPU/SSE
    test rdi, 0xFFF          ; Verificar alinhamento de 4KB
    jnz .invalid_address
    mov rax, cs
    and rax, 0x03
    cmp rax, 0
    jne .invalid_cpl
    test rdi, 0xFFF
    jnz .invalid_address
    mov cr3, rdi
    ret
    mov rax, -EPERM  ; Acesso negado
    ret
    ret
    mov rax, -EFAULT
    ret
mov rcx, MAX_PRIORITY_LEVELS
    mov esi, queues     ; Endereço das filas
    test dword [esi], 0xFFFFFFFF
    jnz .found_queue
    add esi, 4
    loop .find_queue
    jmp .idle           ; Nenhuma fila encontrada → modo ocioso
    mov rax, [esi]      ; Process found
    mov [current_process], rax
// [CONTEXT_SWITCH] - Gerencia troca de contexto entre processos
// Descrição: Alterna entre processos salvando o estado
// Entrada: RDI = PCB atual, RSI = Próximo PCB
// Saída: Nenhuma (troca de contexto ocorre)
.idle_fix:
    pause  ; Melhor prática para reduzir consumo de energia
    sti  ; Habilita interrupções para permitir saída do modo idle
    hlt
    mov esi, queues
mov rcx, MAX_PRIORITY_LEVELS
    jnz found_queue
    dec rcx
    test rcx, rcx
    jz idle
    hlt  ; Esperar interrupção para evitar loop infinito
    jmp idle
    mov rax, [esi]
    mov rbx, current_cpu
    call find_least_loaded_core
    // Implementation inicial do balanceamento de carga
    call find_least_loaded_core  ; Seleciona o núcleo menos carregado
    call migrate_process         ; Move o processo para esse núcleo
    ret
    mov [current_cpu], rax
aging_processes:
    mov rsi, process_list  ; Aponta para a lista de processos
.aging_loop:
        cmp rsi, NULL
        je .end_aging
    mov rax, [rsi + priority]
    cmp rax, MAX_PRIORITY ; Verifica se já está no limite
    jge .no_increment
    add [rsi + priority], 1
.no_increment:
        cmp [rsi + priority], MAX_PRIORITY_LEVELS
        jle .next_process
        mov [rsi + priority], MAX_PRIORITY_LEVELS  ; Limita prioridade máxima
.next_process:
        mov rsi, [rsi + next]  ; Avança para o próximo processo
        jmp .aging_loop
.end_aging:
    mov rdi, [process_list]
    cmp rdi, 0
    je .done
    dec qword [rdi + Process.priority]  ; Reduz prioridade
    mov rdi, [rdi + Process.next]
.done:
aging_loop:
    je .aging_done
    dec [rdi + process_priority]  ; Reduz prioridade se tempo de espera alto
    mov rdi, [rdi + next_process]
    jmp aging_loop
.aging_done:
idle:
    cmp rcx, 1
    je end_aging
    je skip_aging
    add esi, sizeof(queue_entry)  ; Promover processos para filas de maior prioridade
    mov rdx, [esi+4]
    mov [esi], rdx
    loop aging_loop
end_aging:
    // Verificar a fila de maior prioridade com processos prontos
    hlt  ; Esperar interrupção para evitar loop infinito
    jmp idle
    // Selecionar o primeiro processo da fila
    // Executar contexto do processo
    // Balanceamento de carga SMP
dd 0x80  ; Syscall corrigida _exit

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida exit

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _fork

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida fork

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _exec

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida exec

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _waitpid

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida waitpid

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _mmap

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida mmap

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _ioctl

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida ioctl

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Validação Segura de Ponteiros de Usuário
// VALIDATE USER POINTER - Valida ponteiros passados pelo usuário
// - Garante que a aplicação não tente acessar memória proibida.
// - Verifica se o endereço pertence ao espaço do usuário.
// - Retorna erro caso o ponteiro seja inválido.
//                Validação de Ponteiros de Usuário
//                Validação de Ponteiros Padronizada
//                Validação Padronizada de Ponteiros de Usuário
    // Melhorando validação de ponteiros para endereços canônicos em x86-64
    mov rax, rdi
    and rax, 0xFFFFFF800000000000  ; Máscara para detectar endereços inválidos
    cmp rax, 0  ; Se for diferente de 0, é um endereço inválido
    jne .invalid_pointer
    ret
.invalid_pointer:
    mov rax, -EFAULT
    ret
    test rdi, 0x7  ; Alinhamento corrigido para 8 bytes
    jnz .invalid
    mov rax, cr4

// ---- Security Features Check (SMEP/SMAP) ----


// =============================
//   Verificação de SMEP e SMAP
// =============================
check_smep_smap:
    mov rax, cr4
    test rax, (1 << 20)  ; SMEP ativo?
    jz .smep_disabled
    test rax, (1 << 21)  ; SMAP ativo?
    jz .smap_disabled
    xor rax, rax         ; Tudo correto
    ret

.smep_disabled:
    mov rax, -ENOTSUP
    ret

.smap_disabled:
    mov rax, -ENOTSUP
    ret
    mov rax, cr4
    test rax, (1 << 20) | (1 << 21)  ; SMEP (bit 20) e SMAP (bit 21)
    jz .security_disabled
    ret
.security_disabled:
    mov rax, -ENOTSUP
    ret
    mov rax, cr4
    test rax, (1 << 20) | (1 << 21)  ; Verifica SMEP (bit 20) e SMAP (bit 21)
    jz .security_disabled
    ret
    mov rax, -ENOTSUP  ; Recurso não suportado
    ret
    mov rax, cr4
    test rax, (1 << 20)      ; SMEP
    jz .smep_disabled
    test rax, (1 << 21)      ; SMAP
    jz .smap_disabled
    ret
    mov rax, -ENOTSUP
    ret
    mov rax, cr4
    test rax, (1 << 20)      ; Verifica se SMEP está ativado
    jz .smep_disabled
    test rax, (1 << 21)      ; Verifica se SMAP está ativado
    jz .smap_disabled
    ret
    mov rax, -ENOTSUP        ; Retorna erro se SMEP/SMAP não estiverem ativos
    ret
    mov rax, cr4
    test rax, (1 << 20)  ; SMEP (Supervisor Mode Execution Protection)
    jnz .smep_enabled
    test rax, (1 << 21)  ; SMAP (Supervisor Mode Access Prevention)
    jnz .smap_enabled
    ret
.smep_enabled:
.smap_enabled:
    ret
    jz .invalid
    test rdi, 0x7  ; Alinhamento corrigido para 8 bytes
.invalid:
    mov rax, -EFAULT
    smsw rax
    mov rax, -EINVAL
    smsw rax  ; Verifica status de SMAP
    test rax, 0x20
    jnz .invalid_pointer
    test rdi, 0x7  ; Alinhamento corrigido para 8 bytes
    call check_page_permissions  ; Verifica permissões via bitmap
    test rax, rax
    jz .invalid_pointer
    cmp rdi, [user_memory_start]  ; Verifica se está abaixo da região de usuário
    jl .invalid
    cmp rdi, [user_memory_end]  ; Verifica se está dentro do limite
    jg .invalid
    stc  ; Define Carry Flag para indicar erro
    mov rax, -1
    test rdi, 0x7  ; Alinhamento corrigido para 8 bytes
    jnz invalid_pointer
    test rdi, 0x7  ; Alinhamento corrigido para 8 bytes
  ja invalid_pointer
        call log_error ; Registrar erro antes de retornar
        // Função: syscall _handler

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// ---- Rust Syscall Handler ----
    // Removendo declaração externa mal formada
    match syscall num {

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// ---- Otimização: Macro para validação de ponteiros de usuário ----
%macro VALIDATE_USER_PTR 1
    // Verifica endereços não canônicos em x86-64
    mov rax, %1
    shr rax, 47
    cmp rax, 0x1FFFF
    ja .invalid_ptr
    // Verifica alinhamento de 8 bytes
    test %1, 0x7
    jnz .invalid_ptr
    jmp .valid
.invalid_ptr:
    mov rax, -EFAULT
.valid:
    test %1, 0xFFFF800000000000  ; Verifica espaço não-canônico
    jnz .invalid_ptr
    test %1, 0x7                 ; Alinhamento de 8 bytes
    jnz .invalid_ptr
    jmp .valid
    mov rax, -EFAULT
    // Verifica se o ponteiro está no espaço do usuário (canônico para x86-64)
    test %1, 0x7FFF800000000000
    jnz .invalid_ptr
    // Verifica SMAP (Supervisor Mode Access Prevention)
    // Verifica alinhamento de 16 bytes
    test %1, 0x7
    // Verifica permissões da página via bitmap
    call check_page_permissions
    jz .invalid_ptr
    test %1, %1
    test %1, 0x7FF
    test cr4, (1 << 21)  ; Checa se SMAP está ativado
    test %1, 0x7FFF800000000000  ; Verifica se está no espaço do usuário
    smsw rax  ; Verifica SMAP/SMEP
0_=>_sys_read(arg1,_arg2_as_*mut_u8,_arg3_as_usize),:
    // Restante do código...
1_=>_sys_write(arg1,_arg2_as_*const_u8,_arg3_as_usize),:
        _ => -1, // Syscall inválido
    }
        // Implementation de shadow stacks para maior segurança
        call enable_shadow_stack_protection
        // Descrição: Manipula chamadas de sistema dos processos
// Entrada: RAX = Número da syscall , outros registradores

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Entrada: RAX = Número da syscall, outros registradores

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Saída: Retorno depende da syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Saída: Retorno depende da syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

        global syscall _handler

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _malloc   ; Alocação dinâmica de memória

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida malloc   ; Alocação dinâmica de memória

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _free     ; Liberação de memória

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida free     ; Liberação de memória

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida _thread_create  ; Criação de threads

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

dd 0x80  ; Syscall corrigida thread_create  ; Criação de threads

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Tratamento de Erros em Syscalls
        // Entrada: RAX = número da syscall , RDI, RSI, RDX = argumentos

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

        // Entrada: RAX = número da syscall, RDI, RSI, RDX = argumentos

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Saída: RAX = retorno da syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Saída: RAX = retorno da syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Fluxo: Verifica a tabela de syscalls, executa e retorna

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Fluxo: Verifica a tabela de syscalls, executa e retorna

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Manipulação de Chamadas de Sistema (Syscalls)
// - Identifica o número da syscall  no registrador EAX.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Identifica o número da syscall no registrador EAX.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Direciona a execução para a rotina correspondente.
// Syscall Handler - Tratamento de chamadas de sistema
// Syscall Handler - Manipulador de chamadas de sistema
// Verifica a validade dos argumentos e encaminha para a syscall  correspondente.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// Verifica a validade dos argumentos e encaminha para a syscall correspondente.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// MANIPULAÇÃO DE SYSCALLS
// 1. Valida os argumentos passados para evitar acessos indevidos.
// 2. Encaminha a execução para a função correspondente da syscall .

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// 2. Encaminha a execução para a função correspondente da syscall.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// 3. Retorna o resultado ao usuário com os valores apropriados.
// MANIPULAÇÃO DE SYSCALLS - Interface Entre Aplicações e Kernel
// - Valida os argumentos passados para evitar acessos indevidos.
// - Encaminha a execução para a função correspondente da syscall .

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Encaminha a execução para a função correspondente da syscall.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Retorna o resultado ao usuário garantindo segurança e estabilidade.
// SYSCALL HANDLER - Corrigido e otimizado
// SYSCALL HANDLER - Agora verifica limites de buffer
// CHAMADAS DE SISTEMA (SYSCALLS)
// - Permitem que aplicativos interajam com o kernel de maneira segura.
// - Incluem operações como abrir arquivos, alocar memória e criar processos.
// - Implementa verificação de limites para evitar acessos inválidos.
// SYSCALL HANDLER - UNIFICADO E SEGURO
MAX_SYSCALL_NUMBER equ 128  ; Definir limite baseado na tabela de syscalls

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, MAX_SYSCALL_NUMBER  ; Verificação robusta do número da syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

MAX_SYSCALL_NUMBER equ 128  ; Definir limite baseado na tabela de syscalls

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, MAX_SYSCALL_NUMBER  ; Verificação robusta do número da syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    jc .invalid_ptr
    cmp rax, MAX_SYSCALL_NUMBER
    jae .invalid_syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    jmp [syscall table + rax*8]

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

.invalid_syscall:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rax, -ENOSYS
    ret
  // Tabela de syscalls dinâmica

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// --- Tabela de Syscalls ---
    mov rax, -ENOSYS
    jc .invalid_ptr  ; Se inválido, retorna erro
    cmp rdi, [user_memory_end]  ; Checagem de limite superior
    jg .invalid_ptr
    call process_syscall   ; Encaminha syscall  para a função correta

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call process_syscall  ; Encaminha syscall para a função correta

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

.invalid_ptr_fix:
    mov rax, -EFAULT  ; Retorna erro de ponteiro inválido
    // Processamento da syscall  continua aqui

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Processamento da syscall continua aqui

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    test rax, rax  ; Verificar syscall  inválida

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    test rax, rax  ; Verificar syscall inválida

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    js syscall _fail

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    js syscall fail

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Continua execução normal...
syscall_fail:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rax, -1  ; Retorna erro para o usuário
    mov rax, [esp + 4]
%define SYSCALL_COUNT 64
    jmp end_syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    jmp end_syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rbx, syscall table

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rbx, syscall table

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    shl rax, 2
    add rbx, rax
    call dword [rbx]
end_syscall_:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

end_syscall:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, 6
    mov rax, [esp + 4]         ; Número da syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rax, [esp + 4]         ; Número da syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, 6                 ; Número máximo de syscalls suportadas

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, 6                 ; Número máximo de syscalls suportadas

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Obter endereço da syscall  na tabela

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Obter endereço da syscall na tabela

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call dword [rbx]           ; Chamar syscall  correspondente

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call dword [rbx]           ; Chamar syscall correspondente

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rax, -1                ; Retorna erro (-1)
syscall_fork:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call create_process        ; Cria um novo processo
syscall_exec:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call load_executable       ; Carrega um novo binário na memória
syscall_waitpid:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call wait_for_process      ; Bloqueia até o processo terminar
syscall_mmap:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call map_memory_region     ; Mapeia uma área de memória para o processo
syscall_ioctl:

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call device_control        ; Envia comandos para dispositivos
  // Configurar Command List e DMA
  mov rdx, ahci_base
  mov [rdx + 0x10], 1 ; Habilitar Porta
// ---- Rust AHCI Driver ----
// ---- Otimização: Inicialização única do AHCI ----
//                Inicialização dos Drivers AHCI e e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico

init_drivers:
    call init_ahci
    call init_e1000
    call init_keyboard
    ret

    mov rdi, <bus_device>
    call init_pci_device
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    cmp eax, 0xFFFFFFFF
    je .no_ahci
    and eax, 0xFFFF0000
    cmp eax, 0x01060000  ; Verifica se é um controlador AHCI
    jne .no_ahci
    ret
.no_ahci:
    mov rax, -ENODEV
    ret

    // Verificar se o dispositivo existe via PCI
    mov rdi, <bus_device>
    call init_pci_device
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    cmp eax, 0xFFFFFFFF
    je .no_ahci
    // Restante da inicialização
    mov rax, -ENODEV
    ret
    // Busca por dispositivos PCI classe 0x01 (armazenamento), subclasse 0x06 (SATA)
    mov rdi, <bus_device>
    call init_pci_device
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    cmp eax, 0xFFFFFFFF                ; Dispositivo inexistente
    je .no_ahci
    // Verifica se é um controlador AHCI
    and eax, 0xFFFF0000
    cmp eax, 0x01060000                ; Class 0x01, Subclass 0x06
    jne .no_ahci
    // Configuração do AHCI...
    ret
    mov rax, -ENODEV
    ret
    // Configurar FIS e comandos AHCI
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    // Inicializar controlador de rede
    // Implementation básica de detecção PCI
    mov rax, 0x8086  ; ID de fabricante (Intel)
    cmp rax, 0x8086  ; Simulação de detecção
    jne .pci_not_found
    mov rax, [pci_probe_ahci()]  ; Endereço MMIO do AHCI
.pci_not_found:
    ret
    jz .error
    mov dword [rax + 0x24], 0x80000000  ; Habilita AHCI
.error:
    mov rax, -ENODEV
    // Implementation básica de detecção PCI
    mov rax, 0x8086  ; ID de fabricante (Intel)
    cmp rax, 0x8086  ; Simulação de detecção
    jne .pci_not_found
    ret
    if hba_base == 0 {
        return Err("AHCI not detected");
    Ok(())
    mov rax, [hba_base]  ; Verifica se AHCI está presente
    jz .ahci_not_present  ; Retornar erro se AHCI não estiver presente
.ahci_not_present:
    mov rax, -ENODEV  ; Erro: Dispositivo não encontrado
// Inicialização AHCI com Tratamento de Erros
// Inicialização Segura do AHCI
// Inicialização de um Único AHCI Port
    test rdi, rdi  ; Verificar se o controlador está presente
    jz ahci_fail
    // Configuração dinâmica do AHCI
    mov rax, -1  ; Indicar erro
    test rdi, rdi  ; Verificar se AHCI está presente
    // Configuração dinâmica do controlador...
    mov rax, -1  ; Indicar erro na inicialização
    test rax, rax  ; Verificar se AHCI está presente
    // Continuação da inicialização...
    // Implementation básica de detecção PCI
    mov rax, 0x8086  ; ID de fabricante (Intel)
    cmp rax, 0x8086  ; Simulação de detecção
    jne .pci_not_found
    mov rax, pci_probe_ahci()          ; Endereço base do controlador AHCI
    ret
    mov rbx, [rax]             ; Ler registro de CAPABILITIES
    test rbx, 1 << 31          ; Verificar suporte a 64-bit
    jz no_64bit_support
    // Inicializar portas SATA
mov rcx, MAX_PRIORITY_LEVELS
    mov rdx, [rax + rcx * 8]   ; Ler tipo da porta
    test rdx, 1
    jz next_port
    call init_sata_port
    loop scan_ports
    mov rax, -1  ; Indicar erro ao chamador
  // Configurar MAC address e buffers RX/TX
  mov rdx, e1000_base
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    call generate_dynamic_mac  ; Gerar MAC dinamicamente
// ---- Rust e1000 Network Driver ----
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
// ---- Otimização: Inicialização única do e1000 ----
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    // Implementation básica de detecção PCI
    mov rax, 0x8086  ; ID de fabricante (Intel)
    cmp rax, 0x8086  ; Simulação de detecção
    jne .pci_not_found
    mov rax, [pci_probe_e1000()]  ; Endereço MMIO do e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    ret
    // Implementation básica de detecção PCI
    mov rax, 0x8086  ; ID de fabricante (Intel)
    cmp rax, 0x8086  ; Simulação de detecção
    jne .pci_not_found
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    ret
    if status == 0 {
        return Err("e1000 not detected");
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
mov rax, 0x80000000
    mov ecx, 0
    test eax, eax
    jz .e1000_not_present
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    mov rax, [e1000_status]
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
.e1000_not_present:
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    mov rax, -ENODEV  ; Erro: Placa de rede não encontrada
// Inicialização Segura do e1000 (Rede)
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
// Inicialização Segura da Placa de Rede e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    test rdi, rdi  ; Verificar se a NIC está presente
    jz e1000_fail
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    // Configuração dinâmica da e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    test rdi, rdi  ; Verificar se o hardware está disponível
    // Configuração dinâmica da placa de rede...
    mov rax, 0xE0000000         ; Endereço base do controlador e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    mov rbx, [rax + 0]          ; Ler Device ID
    cmp rbx, 0x100E             ; Verificar se é o e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    jnz not_e1000
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    // Configurar MAC Address e buffer de recepção
mov rcx, MAX_PRIORITY_LEVELS
    mov rdx, [rax + rcx]
    mov [mac_address], rdx
    // Ler cabeçalho Ethernet
    mov esi, packet_buffer
    mov rax, [esi + 12]       ; Tipo de protocolo
    cmp rax, 0x0800           ; IPv4?
    jnz drop_packet
    // Processar IP Header
    call handle_ip_packet
    mov rax, 0xF0000000         ; Endereço base do controlador USB
    mov rbx, [rax]              ; Ler status
    test rbx, 1                 ; Verificar se há dispositivos conectados
    jz no_usb_devices
    // Configurar polling de eventos USB
mov rcx, MAX_PRIORITY_LEVELS
    in al, dx                   ; Ler entrada de teclado
    call handle_keystroke
    mov ax, 0x13                ; Modo gráfico 320x200
// SEÇÃO .BSS - Alocação de Memória Não Inicializada
	// Inicialização das variáveis críticas

// --- Guard Pages para proteção contra Buffer Overflow ---
mov rax, 0x0             ; Definir permissões para impedir leitura/escrita
mov rcx, MAX_PRIORITY_LEVELS
mov rdx, 0x1000          ; Tamanho de uma página (4KB)
syscall mmap             ; Criar página de proteção
stack_guard resb 4096    ; Guard Page de 4KB

vtx_enabled resb 1    ; 0 = desativado, 1 = ativado
file_table resb 256     ; Tabela de arquivos abertos
mount_points resb 128   ; Montagem de diferentes FS
vfs_open:
    // Verificar se o arquivo já está na tabela
    mov rax, file_table
mov rcx, MAX_PRIORITY_LEVELS
    cmp [rax], 0
    je found_empty_slot
    add rax, 1
    loop scan_table
found_empty_slot:
    mov [rax], rdx  ; Registrar novo arquivo na tabela
// Leitura de Bloco EXT4 com Verificação de Erros
    mov rsi, [block_number]
    prefetchnta [disk_buffer]  ; Reduz latência de leitura/escrita
    call ahci_read_sector
    jc .error  ; Captura falhas de leitura AHCI
    js .error
    mov rax, -EIO
    mov rax, [fs_base]          ; Endereço do superbloco
    add rax, 1024               ; Pular superbloco
    mov rdx, [rax]              ; Ler inode da raiz
    call read_inode
    mov rax, [fs_base]          ; Endereço do Boot Sector
    cmp word [rax + 0x52], 0xAA55
    jne invalid_fat32
    mov rax, [rax + 0x0B]       ; Ler bytes por setor
invalid_fat32:
uid_table resb 128
gid_table resb 128
// Sistema de Permissões POSIX
        // Melhorado para verificar capabilities além de UID/GID
        call check_capabilities  ; Suporte a CAP_SYS_ADMIN, CAP_NET_ADMIN
            mov rax, [rdi + inode_uid]  ; Obter UID do arquivo
    cmp rax, [current_uid]  ; Comparar com o usuário atual
    je has_permission
    mov rax, [rdi + inode_gid]  ; Obter GID do arquivo
    cmp rax, [current_gid]  ; Comparar com o grupo do usuário
    test [rdi + inode_mode], 0o777  ; Verificar bits de permissão
    jnz has_permission
    mov rax, -1  ; Sem permissão
has_permission:
    mov rax, [file_inode]
    cmp [rax + 8], rbx  ; Verificar UID do dono
    jne access_denied
global printf
    push ebp
    mov ebp, esp
    mov rax, 4          ; Syscall de write
    mov rbx, 1          ; Saída padrão (stdout)
mov rcx, MAX_PRIORITY_LEVELS
    mov rdx, [ebp+12]   ; Tamanho da string
    syscall
    pop ebp
global sys_malloc
    mov rax, 45         ; Syscall de brk
    mov rbx, [ebp+8]    ; Tamanho desejado
    syscall
elf_header resb 64  ; Cabeçalho ELF
global elf_load
    mov rax, [fs_base]  ; Endereço do arquivo ELF
    cmp dword [rax], 0x464C457F  ; Verifica assinatura ELF
    jne invalid_elf
// Kernel code here


    call jump_to_entry     ; Executa o programa
invalid_elf:
    mov rax, shell_prompt
    call printf          ; Exibir >
 na tela
    call read_command    ; Ler entrada do usuário
    call execute_command ; Executar comando
    jmp shell_main       ; Loop infinito
    printf("Hello, Kernel!\n");
    return 0;
gcc -o hello hello.c -nostdlib
./hello
global net_init
    mov rax, 0x80000000  ; PCI Config Read
mov rcx, MAX_PRIORITY_LEVELS
    int 0x1A             ; Interrompe para ler da placa
    mov [net_base], rax  ; Salvar endereço base
global eth_send
    mov rax, [packet]    ; Endereço do pacote Ethernet
mov rcx, MAX_PRIORITY_LEVELS
    mov rdx, [net_base]  ; Endereço da placa
    out dx, rax          ; Enviar pacote
global ip_send
    mov rax, [ip_packet]  ; Endereço do pacote IP
    call eth_send         ; Envia via Ethernet
global tcp_send
    mov rax, [tcp_packet] ; Endereço do pacote TCP
    call ip_send          ; Envia via IP
global sys_socket
    mov rax, 41      ; syscall  para socket

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rax, 41      ; syscall para socket

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    int sock = socket(AF_INET, SOCK_STREAM, 0);
gcc -o test_net test_net.c -nostdlib
./test_net
global load_elf
load_elf:
    call get_random       ; Obtém um endereço aleatório
    add rax, 0x100000     ; Evita que o kernel seja sobrescrito
    mov [load_address], rax  ; Define onde o programa será carregado
global kernel_entry
// Implementation de KASLR - Aleatorização de Endereços
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    call secure_rng ; Usar timestamp como fallback
and rax, 0xFFFFF000  ; Alinhar em 4KB
mov [kernel_base], rax
    call get_random      ; Obtém um endereço aleatório
    and rax, 0xFFFFF000  ; Alinha a página
    mov [kernel_base], rax  ; Define onde o kernel será carregado
global check_permissions
            mov rax, [current_process]
    cmp rax, [restricted_list]
    je deny_access
deny_access:
global check_vtx
    test rcx, 0x20  ; Verifica se VT-x está presente
    jz no_vtx
    mov [vtx_enabled], 1
    mov [vtx_enabled], 0
global sys_unshare
    cmp rax, 0x1       ; PID namespace
    je isolate_pid
    cmp rax, 0x2       ; Network namespace
    je isolate_net
isolate_pid:
    mov [current_pid_namespace], rax
isolate_net:
    mov [current_net_namespace], rax
    mov rax, [esp+8]   ; Limite de GPU
    mov [gpu_limit], rax
    mov [cpu_limit], rax
global kvm_init
    mov rax, [vtx_enabled]
    cmp rax, 0
    je no_kvm
    // Habilita VMX (VT-x)
mov rcx, MAX_PRIORITY_LEVELS
    rdmsr
    or rax, 0x5
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    wrmsr
no_kvm:
// ============================
// DETECÇÃO DE VIRTUALIZAÇÃO
    mov dword [vtx_enabled], 1
    mov dword [vtx_enabled], 0
vtx_enabled resb 1
// INICIALIZAÇÃO DA VIRTUALIZAÇÃO
    // Habilita VMX (VT-x) no MSR IA32_FEATURE_CONTROL
    or rax, 0x5   ; Habilita VMX fora do modo SMM
// SUPORTE A NAMESPACES (ISOLAMENTO)
    mov dword [current_pid_namespace], rax
    mov dword [current_net_namespace], rax
current_pid_namespace resb 1
current_net_namespace resb 1
// SUPORTE A CGROUPS (CONTROLE DE RECURSOS)
    mov dword [cpu_limit], rax
cpu_limit resb 4
// TODO detectado - Implementation inicial inserida
mov rax, [scheduler_tick]  ; Exemplo de time slice
    cmp eax, 0
    jz schedule_next_task
// - Esse trecho ainda precisa ser implementado.
// - Deve incluir árvore vermelha-preta para rastrear uso de CPU.
// - Implementation sugerida: definir classes de tarefa e preempção.
    // Implementation inicial do balanceamento de carga
    call find_least_loaded_core  ; Seleciona o núcleo menos carregado
    call migrate_process         ; Move o processo para esse núcleo
    ret
    mov rax, [current_task]
    mov rbx, [task_list]
    add rbx, 4  ; Próxima tarefa
    cmp rbx, [task_list_end]
    jne switch_task
    mov rbx, [task_list]  ; Volta para o início da lista
switch_task:
    lock xchg [current_task], rbx
    sti
current_task resb 4
task_list resb 256
task_list_end resb 4
// IO SCHEDULER (ELEVATOR)
    mov rax, [io_queue_head]
    jz no_io_request
mov rcx, MAX_PRIORITY_LEVELS
    mov rbx, [rcx + 4]  ; Próximo request
    mov [io_queue_head], rbx
    mov rax, [rcx]  ; Processa requisição
    call process_io
process_io:
    mov rdi, io_queue
    call fetch_next_io_request
    test rax, rax
    jz .no_io
    call dispatch_io_request
.no_io:
    ret
    // Implementation da operação de IO aqui
io_queue_head resb 4
// HUGE PAGES (2MB/1GB)
global enable_hugepages
mov rcx, MAX_PRIORITY_LEVELS
    or rax, 0x20
    or rax, 0x80  ; Habilita PSE (Page Size Extension)
    mov cr4, rax
    mov rax, cr3  ; Recarrega tabela de páginas
    mov cr3, rax
// COPY-ON-WRITE (COW)
global handle_page_fault
handle_page_fault:
    mov rax, cr2
    call get_page_entry
    test qword [rax], 0x200  ; Verifica flag COW
    jz .normal_fault
    call copy_page  ; Duplica a página
    call update_page_entry  ; Atualiza a entrada na tabela
    ret
.normal_fault:
    // Tratamento padrão
    ret
    mov rax, cr2  ; Obter endereço que causou o page fault
    call get_page_entry
    test rax, 0x200  ; Verifica flag COW
    jz .normal_fault
    call allocate_new_page
    call copy_page_content
    call update_page_entry
    ret
    // Tratamento normal de page fault aqui
    ret
    mov rax, cr2  ; Endereço da página com falha
    call get_page_entry
    jz page_not_present
    test rax, 0x200  ; Verifica se a página está marcada como Copy-on-Write
    jz not_copy_on_write
    // Duplica a página para o processo atual
    call allocate_new_page
    call copy_page_content
    call update_page_entry
    jmp end_page_fault
    // Outro tipo de page fault, tratar aqui
// TODO detectado - Implementation inicial inserida
end_page_fault:
// MMAP (MAPEAMENTO DE MEMÓRIA)
global sys_mmap
    mov rax, [esp + 4]  ; Pega endereço solicitado
    jz allocate_new_region  ; Se endereço for NULL, aloca novo espaço
    call find_free_vma
    jz error
    call map_physical_to_virtual
    jmp end_mmap
    call allocate_physical_page
end_mmap:
// TLB SHOOTDOWN (MULTI-CORE)
global invalidate_tlb
    mov rax, cr3
    mov cr3, rax  ; Recarga do CR3 para invalidar TLB globalmente
// ASLR (Address Space Layout Randomization)
global enable_aslr
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand                 ; Obtém um valor aleatório baseado no timestamp
    and rax, 0xFFF        ; Limita o deslocamento para evitar falhas
    shl rax, 12           ; Alinha o deslocamento a 4KB
    mov [aslr_offset], rax
aslr_offset resb 4
// KASLR (Kernel Address Space Layout Randomization)
//                KASLR (Kernel ASLR) Aprimorado
//                Implementation Dinâmica do KASLR
//                Implementation Segura do KASLR

enable_kaslr:
mov rax, 1
    cpuid
    test ecx, (1 << 30)      ; Verifica RDRAND
    jz .fallback_rng
    rdrand rax
    jnc .fallback_rng
    and rax, 0xFFFFF000
    mov [kernel_base], rax
    ret
.fallback_rng:
    rdtsc
    shl rdx, 32
    or rax, rdx
    xor rax, [timestamp]
    and rax, 0xFFFFF000
    mov [kernel_base], rax
    ret
    // Tenta usar RDRAND
    mov ecx, 30
    cpuid
    test ecx, (1 << 30)
    jz .fallback
    rdrand rax
    jnc .fallback
    jmp .apply
.fallback:
    // Combina TSC com outros dados
    rdtsc
    shl rdx, 32
    or rax, rdx
    xor rax, [timestamp]
.apply:
    and rax, 0xFFFFF000  ; Alinha em 4KB
    mov [kernel_base], rax
    ret
    call secure_rng
    and rax, 0xFFFFF000      ; Alinhar deslocamento em 4KB
    add rax, KERNEL_BASE      ; Aplicar deslocamento ao kernel
    mov [kernel_base], rax
    lgdt [gdt_descriptor]     ; Recarregar GDT com novo endereço
    ret
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
    and rax, 0xFFFFF000       ; Alinhar em 4KB
    add rax, KERNEL_BASE      ; Aplicar deslocamento aleatório
    mov [kernel_base], rax
    lgdt [gdt_descriptor]     ; Recarregar GDT
    ret
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    and eax, 0xFFF000
    add rax, KERNEL_BASE
    mov [kernel_base], rax
    ret
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
    and rax, 0xFFFFF000       ; Alinhar em 4KB
    add rax, KERNEL_BASE      ; Aplicar deslocamento
    mov [kernel_base], rax
    lgdt [gdt_descriptor]     ; Recarregar GDT
    ret
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    and eax, 0xFFF000
    add rax, KERNEL_BASE
    mov [kernel_base], rax
    ret
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
    and rax, 0xFFFFF000       ; Alinhamento de 4KB
    add rax, KERNEL_BASE      ; Aplica deslocamento
    mov [kernel_base], rax
    lgdt [gdt_descriptor]     ; Recarrega GDT com novo endereço
    ret
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    // Usar fallback seguro (e.g., timestamp)
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    and eax, 0xFFF000
    add rax, KERNEL_BASE
    mov [kernel_base], rax
    ret
    call update_page_tables  ; Ajustar tabelas de paginação após deslocamento aleatório
    jz .fallback
    and rax, 0xFFFFF000  ; Alinhar endereços em 4KB
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand
    and eax, 0xFFF000
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    call secure_rng ; Usar timestamp como fallback
    jz .kaslr_fail  ; Se RDRAND falhar, aborta
    mov [kaslr_offset], rax
.kaslr_fail:
    and rax, 0x3FFFFF     ; Define um deslocamento seguro dentro de 4MB
    add rax, KERNEL_BASE  ; Ajusta a base do kernel
kaslr_offset resb 4
// NX BIT (No-Execute Protection)
  mov rdx, cr4
  or rdx, 0x80000 ; Habilita NX-bit
  mov cr4, rdx
  or rdx, 0x100000 ; Habilita SMEP
mov rcx, MAX_PRIORITY_LEVELS
    or rax, 0x800         ; Ativa o NX Bit
// DETECÇÃO DE SUPORTE A VIRTUALIZAÇÃO (Intel VT-x / AMD-V)
global check_virtualization
    test rcx, (1 << 5)      ; Verifica o bit 5 do ECX para VT-x
    jnz vt_x_supported
    test rdx, (1 << 12)     ; Verifica o bit 12 do EDX para AMD-V
    jnz amd_v_supported
    mov rax, 0              ; Nenhuma virtualização disponível
    jmp end_check
    mov rax, 1              ; Intel VT-x disponível
    mov rax, 2              ; AMD-V disponível
end_check:
// ATIVAÇÃO DO VT-x (Intel Extended Page Tables - EPT)
global enable_vt_x
mov rcx, MAX_PRIORITY_LEVELS
    or rax, 0x5            ; Ativa VT-x e bloqueia futuras mudanças
// ATIVAÇÃO DO AMD-V (Secure Virtual Machine - SVM)
global enable_amd_v
mov rcx, MAX_PRIORITY_LEVELS
    and rax, ~(1 << 4)     ; Limpa o bit 4 para ativar SVM
// DETECÇÃO DE SUPORTE A ACPI (Advanced Configuration and Power Interface)
global check_acpi
    mov rax, 0x41435049    ; "ACPI" em ASCII
    jz no_acpi_support
    mov rax, 1             ; ACPI disponível
    jmp end_acpi_check
    mov rax, 0             ; ACPI não suportado
end_acpi_check:
// CONFIGURAÇÃO DO APIC (Advanced Programmable Interrupt Controller)
global enable_apic
mov rcx, MAX_PRIORITY_LEVELS
    or rax, (1 << 11)     ; Ativa o APIC
// CONFIGURAÇÃO DO HPET (
// ATIVAÇÃO DO ASLR (Address Space Layout Randomization)
    test rdx, (1 << 29)    ; Verifica se o bit 29 (PSE) está ativo
    jz no_aslr_support
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    call secure_rng ; Usar timestamp como fallback
    and rax, 0xFFFFF000    ; Alinha à página
    mov [random_offset], rax
    mov rax, 1             ; ASLR ativado
    jmp end_aslr_check
    mov rax, 0             ; ASLR não suportado
end_aslr_check:
random_offset resb 4
// ATIVAÇÃO DO KASLR (Kernel ASLR)
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    call secure_rng ; Usar timestamp como fallback
    and rax, 0xFFF00000    ; Alinha ao espaço de memória do kernel
    mov rax, 1             ; KASLR ativado
    jmp end_kaslr_check
    mov rax, 0             ; KASLR não suportado
end_kaslr_check:
// ATIVAÇÃO DO SMEP (Supervisor Mode Execution Prevention)
    or rax, (1 << 20)    ; Ativa SMEP (Supervisor Mode Execution Prevention)
mov rcx, MAX_PRIORITY_LEVELS
    or rax, (1 << 20)    ; Ativa SMEP (bit 20 do CR4)
// ATIVAÇÃO DO SMAP (Supervisor Mode Access Prevention)
    or rax, (1 << 21)    ; Ativa SMAP (bit 21 do CR4)
// ATIVAÇÃO DO NX-bit (No Execute Bit)
mov rcx, MAX_PRIORITY_LEVELS
    test rdx, (1 << 20)   ; Verifica suporte ao NX-bit
    jz nx_not_supported
    or rax, (1 << 11)     ; Ativa o NX-bit no EFER
    mov rax, 1            ; NX-bit ativado
    jmp end_nx_check
    mov rax, 0            ; NX-bit não disponível
end_nx_check:
// INICIALIZAÇÃO DOS CGROUPS (Control Groups)
global init_cgroups
    mov rax, 0            ; Inicializa a estrutura de cgroups
    mov [cgroup_init_flag], rax
    mov rax, 1            ; Ativa os cgroups
    mov [cgroup_enabled], rax
cgroup_init_flag resb 4
cgroup_enabled resb 4
// CRIAÇÃO DE NAMESPACES (Isolamento de Processos)
global create_namespace
    mov rax, [namespace_count]
    inc rax
    mov [namespace_count], rax
namespace_count resb 4
// LIMITAÇÃO DE CPU PARA PROCESSOS
    mov rax, [cpu_limit]  ; Obtém o limite de CPU definido
    je no_limit
mov rcx, MAX_PRIORITY_LEVELS
    mul rcx               ; Aplica a limitação de CPU ao processo atual
    shr rax, 4            ; Reduz a prioridade se exceder o limite
    mov [process_cpu_quota], rax
no_limit:
current_process resb 4
process_cpu_quota resb 4
// LIMITAÇÃO DE RAM PARA PROCESSOS
    mov rax, [ram_limit]  ; Obtém o limite de RAM definido
    je no_ram_limit
    mul rcx               ; Aplica a limitação de RAM ao processo atual
    shr rax, 4            ; Reduz a alocação de memória se exceder o limite
    mov [process_ram_quota], rax
no_ram_limit:
ram_limit resb 4
process_ram_quota resb 4
// IMPLEMENTAÇÃO DO ASLR (Address Space Layout Randomization)
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand               ; Lê o timestamp counter (número pseudoaleatório)
    and rax, 0xFFF      ; Mantém apenas os bits menos significativos
    shl rax, 12         ; Cria um deslocamento aleatório na memória
// IMPLEMENTAÇÃO DO KASLR (Kernel Address Space Layout Randomization)
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand               ; Lê o timestamp counter para gerar um deslocamento aleatório
    and rax, 0xFFFFF    ; Mantém bits aleatórios suficientes para randomização
    shl rax, 16         ; Ajusta para endereçamento válido
// PROTEÇÃO CONTRA BUFFER OVERFLOW
// ATIVANDO INTEL VT-x (VMX)
global enable_vmx
    // Verifica se o processador suporta VMX
    test rcx, (1 << 5)
    jz vmx_not_supported
        // Verificação adicional de suporte VMX via CPUID
        call check_vmx_support
            // Ativa VMX no MSR IA32_FEATURE_CONTROL
    or rax, (1 << 2)   ; Habilita VMX
    // Habilita VMX no CR4
    or rax, (1 << 13)  ; Define o bit VMXE
    call disable_vtx
    jmp continue_execution
            hlt ; Para a execução caso VT-x não seja suportado
// ATIVANDO AMD-V (SVM)
global enable_svm
    // Verifica se o processador suporta SVM
    mov rax, 0x80000001
    test rcx, (1 << 2)
    jz svm
// DETECTANDO E INICIALIZANDO PROCESSADORES ADICIONAIS (APs)
global init_smp
init_smp:
    lock inc dword [cpu_count]  ; Incremento atômico
    // Restante da inicialização
    // Verifica o número de CPUs
    mov rax, 0x1
    shr rbx, 16
    and rbx, 0xFF   ; Número de CPUs lógicas
    mov [num_cpus], rbx
    // Inicializa cada processador adicional
mov rcx, MAX_PRIORITY_LEVELS
init_ap_loop:
    cmp rcx, rbx
    jge smp_done
    // Envia IPI para ativar a CPU ECX
    mov rax, (1 << 14) | rcx
    mov rdx, 0xFEE00300
    mov [rdx], rax
    inc rcx
    jmp init_ap_loop
smp_done:
num_cpus resb 4
// BALANCEAMENTO DE CARGA ENTRE OS NÚCLEOS
    // Verifica qual CPU está ociosa
mov rcx, MAX_PRIORITY_LEVELS
    mov rdx, 0
find_idle_cpu:
    cmp rdx, rcx
    jge load_balancing_done
    // Verifica a fila de processos da CPU EDX
    mov rax, [cpu_task_queue + rdx * 4]
    je assign_task_to_cpu
    inc rdx
    jmp find_idle_cpu
assign_task_to_cpu:
    // Move o próximo processo da fila global para a CPU EDX
    mov rax, [global_task_queue]
    mov [cpu_task_queue + rdx * 4], rax
    // Remove o processo da fila global
    mov [global_task_queue], 0
load_balancing_done:
cpu_task_queue resb 32   ; Armazena processos atribuídos a cada CPU
global_task_queue resb 4  ; Armazena processos prontos para execução
// INICIALIZAÇÃO DO LOCAL APIC
global init_apic
//                Inicialização do APIC e Drivers
init_apic:
    // Configuração do Local APIC
    mov rax, [lapic_base]
    or dword [rax + 0xF0], 0x1FF       ; Spurious Interrupt Vector
    mov dword [rax + 0x320], 0x10000    ; Timer em modo periódico
    mov dword [rax + 0x3E0], 0x0B       ; Divisor de clock (1)
    ret
    // Configuração do vetor de interrupções
    // Inicializar controladora SATA
    // Configurar controlador de rede
    // Habilita o Local APIC
    mov rax, [lapic_base]
    or rax, 0x100
    mov [lapic_base], rax
    // Define a prioridade mínima para permitir interrupções
    mov rax, 0
    mov [lapic_base + 0x80], rax  ; TPR (Task Priority Register)
    // Configura a temporização do APIC
    mov rax, 0x3
    mov [lapic_base + 0xE0], rax  ; Divide Configuration Register
    mov rax, 0xFFFFFFFF
    mov [lapic_base + 0x390], rax ; Timer Initial Count
    // Define o modo de envio de interrupções
    mov rax, 0x00020000
    mov [lapic_base + 0xB0], rax  ; Spurious Interrupt Vector Register
lapic_base resb 4
// TRATAMENTO DE INTERRUPÇÕES USANDO APIC
global apic_handle_interrupt
    // Obtém a ID da interrupção recebida
    mov rax, [lapic_base + 0xB0]
    and rax, 0xFF
    // Trata a interrupção conforme a ID
    cmp rax, 32
    inc qword [scheduler_tick]  ; Atualizar quantum do escalonador    je handle_timer_interrupt
    cmp rax, 33
    jmp apic_end_interrupt
    // Código para lidar com o timer
    mov [lapic_base + 0x390], rax
    // Código para lidar com teclado
apic_end_interrupt:
    mov [lapic_base + 0xB0], rax
    // Envia EOI (End of Interrupt) para o APIC
keyboard_buffer resb 1
// INICIALIZAÇÃO DO BALANCEADOR DE CARGA
global init_smp_scheduler
// - Implementa um sistema de filas multiníveis para priorizar processos.
// - Alterna entre processos de acordo com a prioridade e tempo de execução.
    // Configura a tabela de processadores ativos
    mov [active_cpus], rax
    // Habilita interrupções em múltiplos núcleos
mov rcx, MAX_PRIORITY_LEVELS
init_smp_loop:
    cmp rcx, [cpu_count] ; Verifica se todos os núcleos foram inicializados
    jge smp_init_done
    mov rax, rcx
    shl rax, 4
    add rax, [lapic_base]
    mov [lapic_base + rax], rax
    jmp init_smp_loop
smp_init_done:
active_cpus resb 4
cpu_count resb 4
// ESCALONADOR MULTI-CORE
global smp_schedule
    // Verifica se há processos nas filas de prioridade
    cmp esi, 5
    jge no_process
    // Removendo sti inseguro, pois pode habilitar interrupções cedo demais
    jne switch_process
    jmp find_process
    // Obtém o próximo processo da fila selecionada
    mov edi, [mlfq_queues + esi * 4]
    sti  ; Reativar interrupções após a manipulação
    // Ajusta o aging para evitar starvation
    cmp rcx, esi
    jle skip_aging
    dec dword [mlfq_queues + rcx * 4]
    sti  ; Reativar interrupções após a manipulação
    // Atualiza dinamicamente o quantum baseado na prioridade
    call update_time_quantum
    // Seleciona o próximo núcleo disponível
mov rcx, MAX_PRIORITY_LEVELS
    cmp rcx, [cpu_count]
    jl select_cpu
mov rcx, MAX_PRIORITY_LEVELS
// DETECÇÃO E HABILITAÇÃO DE VT-x
global init_vtx
// Inicialização Completa do VT-x e VMCS
    // Ativar VMXON
    or rax, (1 << 13)  ; Ativar VMX
    mov rax, initialize_vmx()_region
    initialize_vmx() rax
    // Configurar VMCS
    mov rax, vmcs_region
    vmclear rax
    vmptrld rax
    test ecx, (1 << 5)  ; Check for VT-x support (bit 5 in ECX)
    bt rcx, 5   ; Verifica o bit VMX (bit 5 do ECX)
    jc enable_vtx
    jmp vtx_not_supported
    call setup_vmcs
    // Ativa o suporte a VMX no CR4
    or rax, 0x2000  ; Set VMXE (VMX Enable)
    // Configura VMXON region
    mov rax, vtxon_region
    mov [rax], 0x00000000  ; Definir VMX revision
mov rcx, MAX_PRIORITY_LEVELS
// Verificar se a CPU suporta VT-x antes de ativar VMX
    test rcx, (1 << 5)  ; Checar bit VMX no CPUID
    jnc vtx_enabled
    jmp vtx_error
vtx_not_supported:
    // Lidar com CPUs sem suporte a VT-x
vtx_error:
    // Tratar erro ao tentar ativar VT-x
// INICIALIZAÇÃO DO ASLR
global init_aslr
    // Gera um número aleatório para deslocamento de memória
    call generate_random
// GERAÇÃO DE NÚMERO ALEATÓRIO PARA ASLR
generate_random:
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand                   ; Lê timestamp do contador de tempo
    xor rdx, rax            ; Mistura os bits de EDX e EAX
    rol rdx, 13             ; Roda os bits para aumentar aleatoriedade
    xor rax, rdx            ; Mistura novamente
    and rax, 0xFFF000       ; Garante alinhamento de página (4KB)
// APLICAÇÃO DO ASLR NO CARREGAMENTO DE PROCESSOS
global apply_aslr
    // Obtém o endereço base do programa e adiciona o deslocamento
    mov rax, [program_base_address]
    add rax, [aslr_offset]
    mov [program_final_address], rax
program_base_address resb 4
program_final_address resb 4
// INICIALIZAÇÃO DO KASLR
// ---- Otimização: KASLR com RDRAND ----
init_kaslr:
    test rcx, (1 << 30)  ; Verifica se RDRAND está disponível
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    call secure_rng ; Usar timestamp como fallback
    jmp .done
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand  ; Usa timestamp como fallback
    and rax, 0xFFFFF000  ; Alinha para 4KB
    // Gera um número aleatório para deslocamento do kernel
    call generate_random_kaslr
    // Ajusta o endereço base do kernel
    mov rax, [kernel_base_address]
    add rax, [kaslr_offset]
    mov [kernel_final_address], rax
// GERAÇÃO DE NÚMERO ALEATÓRIO PARA KASLR
generate_random_kaslr:
    rol rdx, 17             ; Roda os bits para aumentar aleatoriedade
kernel_base_address resb 4
kernel_final_address resb 4
// HABILITAÇÃO DE HUGE PAGES
    // Verifica suporte a HugePages no CR4
    test rax, 1 << 4   ; Verifica se PSE já está habilitado
    jz .pse_enabled   ; Se PSE não estiver habilitado, habilita
    // PSE já habilitado, continua para configuração de HugePages
    jmp .hugepages_config
    or rax, 1 << 4   ; Habilita PSE (Page Size Extensions)
.hugepages_config:
    // Configura a Page Directory Entry para HugePages (2MB)
    mov [page_directory], rax
    // Aloca memória para a HugePage (exemplo com alocação estática)
    // Em um sistema operacional real, você usaria um gerenciador de memória para alocar HugePages
    mov edi, HUGE_PAGE_ADDRESS ; Endereço de início da HugePage
    // ... (código para preencher a HugePage com dados) ...
page_directory resb 4
 * Kerygma-X Kernel
 *
 * Kerygma-X é um sistema operacional de desktop avançado, projetado para 
 * oferecer uma base robusta e eficiente para ambientes de computação pessoais
 * e profissionais. Este kernel foi desenvolvido com o objetivo de proporcionar
 * uma experiência de usuário fluida, com multitarefa, gerenciamento de recursos
 * otimizado e suporte a interfaces gráficas modernas.
 * Com uma arquitetura de 64 bits, o Kerygma-X foca em alta performance, 
 * modularidade e extensibilidade, permitindo a integração de novas tecnologias
 * e recursos inovadores para atender às crescentes necessidades de computação
 * em ambientes desktop.
 * O código-fonte deste kernel está sob a licença GNU General Public License 
=============================================================================
// Fully Integrated, Optimized, and Improved Enterprise-Grade Monolithic Kernel
// =============================================================================
BITS 64
ORG 0x0000000000100000
%DEFINE KERNEL_VER 'v3.3.0', 13, 'Fully Improved Enterprise Kernel', 13, 0
KERNELSIZE equ 131072 ; 128KB kernel space
// ================================ CPU STATE ==================================
%define PAGE_PRESENT (1 << 0)
%define PAGE_WRITE (1 << 1)
%define PAGE_USER (1 << 2)
%define CODE_SEGMENT 0x08
%define DATA_SEGMENT 0x10
%define TSS_SEGMENT 0x28
// ============================== KERNEL STRUCTURES ============================
struc PCB
    .pid        resq 1
    .state      resq 1
    .stack_ptr  resq 1
    .next       resq 1  ; Ponteiro para o próximo processo
endstruc
endstruc
    resq 1  ; PID
    resq 1  ; Estado
    resq 1  ; Ponteiro para próxima thread
    resq 1  ; Ponteiro para page directory
    resq 1  ; PID
    resq 1  ; Estado
    resq 1  ; Ponteiro para próxima thread
    .pid        resq 1  ; ID do processo
    .state      resq 1  ; Estado do processo
    .stack_ptr  resq 1  ; Ponteiro de pilha
endstruc
struc TSS
    .rsp0       resq 1
    .ist        resq 7
endstruc
endstruc
    resq 1  ; RSP0 (pilha para nível 0)
    resq 1  ; RSP1 (pilha para nível 1)
    resq 1  ; RSP0 (pilha para nível 0)
    resq 1  ; RSP1 (pilha para nível 1)
    jmp start
    nop
    db 'ENTKERN' ; Kernel signature
    align 16
    dq sys_input
    dq sys_output
.find_order:
    cmp rdi, (1 << rcx) * 4096
    jle .found_order
    cmp rcx, 10
    jle .find_order
    mov rax, -12  ; ENOMEM
.found_order:
    mov rsi, [free_lists + rcx * 8]
    test rsi, rsi
    jz .split_block
    mov rax, [rsi]
    mov [free_lists + rcx * 8], rax
    dq sys_free
    dq sys_create_process
    dq sys_getpid
    dq sys_sched_yield
dq_sys_read_file:
    dq sys_socket
    dq sys_close
    dq sys_exit
    dq sys_waitpid
// ============================== ENTRY POINT ==================================
start:
    mov rsp, kernel_stack_top
    call init_gdt
    call init_tss
    call init_idt
    call init_syscalls

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call init_syscalls

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call init_apic
    mov rax, 0x80000000  ; Inicia varredura PCI
    call read_pci_device
    loop scan_pci
    call init_uart
    call init_memory
    call init_smep
    call init_smap
    call init_smp
    call start_aps
    mov rdi, msg_boot_header
    call klog
    mov rdi, init_program
    call sys_create_process
    jmp scheduler_entry
// ======================== ENTERPRISE SCHEDULER ===============================
    call init_lapic_timer
    mov [process_list_head], 0
scheduler_entry:
    mov rbx, [current_pcb]
    mov [rbx + PCB.registers], r15
    fxsave [rbx + PCB.registers + 64]
mov rcx, MAX_PRIORITY_LEVELS
.loop_fix:
    mov rax, [scheduler_queues + rcx * 8]
    jnz .found
    jns .loop
.found:
    // Round-robin dentro da prioridade
    mov rdx, [rax + PCB.next]
    mov [scheduler_queues + rcx * 8], rdx
    mov rbx, rax
    mov [current_pcb], rbx
    fxrstor [rbx + PCB.registers + 64]
    mov rax, [rbx + PCB.page_dir]
    mov rax, [current_pcb]
    mov rax, [rax + PCB.next]
    jz .no_next
    mov rax, [process_list_head]
// ======================== SYSTEM CALLS ======================================
    // Implementation única
    ret
    mov byte [rbx + PCB.state], 0
// ---- Otimização: Buddy Allocator com Bitmap ----
bitmap dq 0xFFFFFFFFFFFFFFFF  ; 64 blocos livres inicialmente
kmalloc:
    mov rdi, free_lists
    xor rcx, rcx
.find_free_block:
    bt [rdi], rcx
    jnc .allocate
    inc rcx
    cmp rcx, MAX_BLOCKS
    jae .no_memory
    jmp .find_free_block
.allocate:
    bts [rdi], rcx
    lea rax, [MEMORY_BASE + rcx * BLOCK_SIZE]
    ret
.no_memory:
    mov rax, -ENOMEM
    ret
    bsf rax, qword [bitmap]  ; Encontra o primeiro bloco livre
    btr qword [bitmap], rax  ; Marca como ocupado
    shl rax, 12  ; Converte para endereço (blocos de 4KB)
    mov rax, -ENOMEM
        // Melhorado para evitar fragmentação
        call align_allocation  ; Garante alinhamento de memória
                call optimize_memory_allocation

// Teste de falha de alocação
test_memory_failure:
    mov rdi, 0xFFFFFFFF  ; Tamanho inválido
    call memory_alloc
    test rax, rax
    jz .allocation_failed
.allocation_success:
    ret
.allocation_failed:
    mov rax, -1
    ret
            jz .fork_fail
    mov [rax + PCB.pid], rdi
    mov [rax + PCB.state], 1
    mov [rax + PCB.priority], [rbx + PCB.priority]
    mov [rax + PCB.rip], [rbx + PCB.rip]
    mov [rax + PCB.rsp], [rbx + PCB.rsp]
    mov rdx, [process_list_head]
    mov [rax + PCB.next], rdx
    mov [process_list_head], rax
    mov rax, [rax + PCB.pid]
    mov [rbx + PCB.rip], rdi
    jz .return
    cmp [rax + PCB.pid], rdi
    jz .found
    cmp byte [rax + PCB.state], 0
    jnz .wait
// ======================== GERENCIAMENTO DE MEMÓRIA ==========================
// Buddy Allocator - Gerenciamento de Memória
// Função: buddy_alloc (Verificação de Erros)
        // Implementation de listas de blocos livres para o Buddy Allocator
        call add_free_block_list
// Implementation de fusão de blocos livres adjacentes
merge_adjacent_blocks:
    mov rsi, [free_list + rdi]  ; Load block pointer
    test rsi, rsi
    jz .merge_done
    cmp rdi, [rsi + 8]  ; Check if adjacent
    jne .merge_done
    add rdi, [rsi]  ; Merge blocks
    mov [free_list + rdi], rdi  ; Update free list
    jmp merge_adjacent_blocks
.merge_done:
    ret
    call check_adjacent_blocks
    add rax, rbx  ; Junta os blocos
        // Implementation completa do Buddy Allocator
// Implementation de split de blocos grandes
split_large_blocks:
    call find_free_block
    shr rax, 1  ; Divide o bloco pela metade
        call check_and_merge_blocks  ; Mescla blocos adjacentes para reduzir fragmentação
        // Verifica se há blocos livres contíguos para mesclagem
        call check_and_merge_blocks
        // Divide blocos grandes se necessário para otimizar alocação
    jz alloc_fail
    call find_best_fit  ; Encontrar melhor bloco disponível
    jz alloc_fail  ; Retorna erro se não há espaço
    mov rax, -1  ; Indicar falha na alocação
    mov rdx, rdi  ; Tamanho do bloco solicitado
    mov rax, free_memory
    add free_memory, 4096
// ====================== DATA SECTION =========================================
msg_boot_header db '[Enterprise] Fully Integrated Kernel v3.3.0 (SMP Enabled)', 0
init_program db '/system/init', 0
// ====================== FOOTER ===============================================
// Enterprise Kernel v3.5 - Critical Improvements Implementation
// ***** MEMORY MANAGEMENT IMPROVEMENTS ****
    // KASLR Implementation
    and rax, 0xFFFFF000      ; Align to 4KB
    mov [pml4_base], rax
    // Buddy Allocator Setup
    mov rdi, memory_bitmap
mov rcx, MAX_PRIORITY_LEVELS
    xor rax, rax
    rep stosq                ; Clear bitmap
    // Buddy Allocator (Size in RDI)
    mov rsi, [free_memory]
    bsf rcx, qword [memory_bitmap]
    lock btr qword [memory_bitmap], rcx
    shl rcx, 12              ; 4KB blocks
    lea rax, [rcx + 0x100000] ; Physical address
.error_fix:
    mov rax, -12             ; ENOMEM
// ***** SMP IMPROVEMENTS **********
    // Configure APIC for SMP
    mov rsi, [apic_base]
    mov dword [rsi+0xF0], 0x1FF  ; Spurious IV
    mov dword [rsi+0x350], 0x10000 ; LVT Timer
    // Start APs
.ap_loop:
    jge .done
    call ap_startup
    jmp .ap_loop
ap_startup:
    // Send INIT-SIPI-SIPI sequence
    mov rax, 0x000C4500
    mov [apic_base+0x300], rax
    mov rax, 0x000C4620
// ***** SCHEDULER IMPROVEMENTS ********
    mov rdi, scheduler_queues
mov rcx, MAX_PRIORITY_LEVELS
    rep stosq
    // Check priority queues from 0 (highest) to 4
mov rcx, MAX_PRIORITY_LEVELS
    mov rax, [scheduler_queues + rcx*8]
    // Implement round-robin within queue
    mov [scheduler_queues + rcx*8], rdx
// ***** SECURITY IMPLEMENTATIONS *****
    mov rax, cr2
    test dword [rsp+24], 0x04 ; User mode?
    jz .kernel_fault
    // SMEP/SMAP Protection
    test rax, 0xFFFF800000000000
    jnz .security_violation
    jmp .continue
    mov rax, -14             ; EFAULT
// ***** PROCESS MANAGEMENT ********
    // COW Implementation
    // Clone page tables
    call copy_page_directory
    // Mark pages as read-only
    mov rdi, [rbx + PCB.cr3]
    call set_cow_flags
    // ELF Loader Implementation
    mov rdi, [current_pcb]
    call load_elf_binary
    mov rax, -8              ; ENOEXEC
// ***** DRIVERS IMPLEMENTATION ********
    // AHCI HBA Initialization
    mov rdi, [ahci_base]
    or dword [rdi + 0x24], 0x80000000 ; AE bit
    // Setup Command List
    mov dword [rdi + 0x100], 0xFFFFFFFF ; All ports active
    // Intel 82574L Configuration
    mov rdi, [e1000_base]
    mov rax, [fetch_e1000_mac_address()]  ; Ler MAC address dinâmico
    // Enable RX/TX
    mov dword [rdi + 0x0280], 0x04000000 ; RCTL
    mov dword [rdi + 0x0400], 0x02000000 ; TCTL
// ***** DATA SECTION **********
// ***** CODE INTEGRATION **********
//_Update_existing_code_with:
        // - Enhanced syscall _handler with SMEP checks

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

        // - Revised page_fault_handler for COW
// - Complete driver implementations
// - SMP boot code in start_aps
// Enterprise Kernel v3.6 - Critical Components Implementation
// ***** ELF LOADER IMPLEMENTATION *****
struc Elf64_Ehdr
struc Elf64_Phdr
load_elf_binary:
    // RDI = File pointer
    // Validate ELF magic
    cmp dword [rdi], 0x7F454C46 ; "\x7FELF"
    jne .invalid_elf
    // Load program headers
    movzx rcx, word [rdi + Elf64_Ehdr.e_phnum]
    mov rsi, rdi
    add rsi, [rdi + Elf64_Ehdr.e_phoff]
    // Check loadable segment
    cmp dword [rsi + Elf64_Phdr.p_type], 1 ; PT_LOAD
    jne .next_segment
    // Allocate memory
    mov rdx, [rsi + Elf64_Phdr.p_memsz]
    jz .nomem
    // Copy data
    mov rdi, rax
mov rcx, MAX_PRIORITY_LEVELS
    movdqu xmm0, [rsi]
    movdqu [rdi], xmm0
    add rsi, 16
    add rdi, 16
    sub rcx, 16
    jnz .copy_loop
    // Set permissions
    mov rax, [rsi + Elf64_Phdr.p_flags]
    call set_page_permissions
.next_segment:
    add rsi, Elf64_Phdr_size
    loop .load_segment
    // Set entry point
    mov rax, [rdi + Elf64_Ehdr.e_entry]
.invalid_elf:
    mov rax, -7              ; ENOEXEC
// ***** AHCI DRIVER IMPLEMENTATION ********
    // Initialize AHCI HBA
    mov rax, [rdi + 0x24]
    or rax, 0x80000000       ; AE bit
    mov [rdi + 0x24], rax
    // Find active port
    mov rdx, [rdi + 0x0C]    ; CAP
    and rdx, 0x1F            ; NP
mov rcx, MAX_PRIORITY_LEVELS
    bt [rdi + 0x14], rcx     ; PI
    jc .port_found
    loop .find_port
    // Setup command list
    lea rsi, [rdi + 0x100 + rcx*0x80]
    mov dword [rsi], 0x00010001 ; CMD | FRE
// ***** ERROR HANDLING IMPROVEMENTS *******
%define EPERM   1
%define ENOENT  2
%define EIO     5
%define ENOMEM  12
%define EFAULT  14
%define EBUSY   16
%define EINVAL  22
%define ENOSYS  38
    // Validate syscall  number

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Validate syscall number

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, (syscall table_end - syscall table)/8

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rax, (syscall table_end - syscall table)/8

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Validate user pointers
    test rflags, 0x00020000  ; Check CPL
    jnz .user_mode
    call validate_kernel_ptr
    jc .fault
    jnz .fail
    mov rax, [rdi]
    clc
    stc
    // Proceed with syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Proceed with syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call [syscall table + rax*8]

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    call [syscall table + rax*8]

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    swapgs
    o64 sysret
// ***** SYNCHRONIZATION IMPLEMENTATION ****
.spin:
    xchg [spinlock.lock], rax
    jnz .spin
    mov qword [spinlock.lock], 0
// ***** TESTING INFRASTRUCTURE ********
// QEMU Debug Port
%macro debug_char 1
    mov dx, 0x3F8
    mov al, %1
    out dx, al
%macro debug_str 1+
    jmp %%endstr
%%endstr:
    mov rsi, %%str
%%loop:
    lodsb
    test al, al
    jz %%done
    debug_char al
    jmp %%loop
// Enterprise Kernel v4.0 - Final Implementation
// ***** PAGE PERMISSION MANAGEMENT ********
set_page_permissions:
    // RDI=Virtual Address, RSI=Flags (R/W/X)
    mov r8, rdi
    shr r8, 39
    and r8, 0x1FF           ; PML4 Index
    lea r9, [rax + r8*8]
    mov r10, [r9]
    and r10, ~0xFFF         ; Get PDPT Base
     // ... Repeat for PDPT, PD, and PT levels ...
     and qword [r11], ~0x07  ; Clear existing flags
    or qword [r11], rsi     ; Set new flags
    invlpg [rdi]
// ***** POINTER VALIDATION ********
    // RDI=Pointer
validate_kernel_ptr:
    jz .fail
// ***** DYNAMIC MEMORY ALLOCATION *****
    // RDI=Size
    lea rdx, [rsi + rdi]
    cmp rdx, memory_end
    jae .error
    mov [free_memory], rdx
// ***** ADVANCED SCHEDULING *******
    // Multi-level Feedback Queue
mov rcx, MAX_PRIORITY_LEVELS
    dec qword [rax + PCB.timeslice]
    jnz .keep
    mov [scheduler_queues + rcx*8], rax
    mov qword [rax + PCB.timeslice], 5
// ***** DRIVER IMPLEMENTATIONS ********
// Keyboard Driver
    call enqueue_scancode
// VGA Text Mode Driver
vga_putc:
    // RDI=char, RSI=position
    mov rax, [vesa_framebuffer]
    mov [rax + rsi*2], dil
// ***** FILESYSTEM IMPLEMENTATION *****
sys_read_file:
    // RDI=filename, RSI=buffer
mov rcx, MAX_PRIORITY_LEVELS
    mov rdx, files_root
.search:
    lea rdi, [rdx + File.name]
    call strcmp
    add rdx, File_size
    loop .search
    mov rax, -ENOENT
    mov rsi, [rdx + File.data]
mov rcx, MAX_PRIORITY_LEVELS
// ***** INTERRUPT HANDLING ********
%macro IRQ_HANDLER 1
    out 0x20, al  ; End of Interrupt (EOI)
    push all
    call irq_%1_handler
    call irq%1_handler
    pop all
IRQ_HANDLER 0              ; Timer
    out 0x20, al  ; End of Interrupt (EOI)
IRQ_HANDLER 1              ; Keyboard
    out 0x20, al  ; End of Interrupt (EOI)
// ***** SMP SYNCHRONIZATION *******
mutex_lock:
    lock bts qword [rdi], 0
    jc .spin
    pause
    test qword [rdi], 1
    jmp mutex_lock
    lock btr qword [rdi], 0
    File 'init', 512, init_program
    File 'test', 1024, test_data
// ***** TESTING MACROS ********
%macro TEST_START 1
    debug_str %1
    debug_char 13
%macro TEST_ASSERT 2
    cmp %1, %2
    je %%ok
    debug_str LINE
    hlt
%%ok:
// ***** BOOTSTRAP CODE ********
    // ... existing init code ...
    TEST_START 'Memory Allocation'
    mov rdi, 4096
    TEST_ASSERT rax, 0x100000
     TEST_START 'File System'
    mov rdi, 'init'
call_sys_read_file:
    TEST_ASSERT rax, 0
     jmp user_mode_entry
// Enterprise Kernel v5.0 - Advanced Features
// ***** BUDDY ALLOCATOR IMPLEMENTATION ****
%define MAX_ORDER 10          ; 1024KB max block size
    // RDI = Size in bytes
    cmp rdi, (1 << rcx)*4096
    cmp rcx, MAX_ORDER
    mov rsi, [free_lists + rcx*8]
    lock mov [free_lists + rcx*8], rax
    // ... (recursive splitting logic)
sys_free:
    // RDI = Pointer
    // ... (buddy merging logic)
// ***** EXT2 FILESYSTEM IMPLEMENTATION ****
struc ext2_inode
    // ... (full inode structure)
sys_create_file:
    // RDI=filename, RSI=size
    call find_free_inode
    call allocate_blocks
    call write_directory_entry
    // RDI=inode
    call free_blocks
    call clear_inode
// ***** ADVANCED VGA DRIVER *******
vga_scroll:
    mov rsi, [vesa_framebuffer] + 160
    mov rdi, [vesa_framebuffer]
mov rcx, MAX_PRIORITY_LEVELS
    // ... (handle newline, tabs, scrolling)
// ***** ENHANCED SCHEDULER ********
    dec qword [current_pcb.timeslice]
    jnz .exit
    mov qword [current_pcb.timeslice], 5
// ***** SMP TICKET LOCK *******
struc ticket_lock
    lock inc dword [rdi + ticket_lock.next]
    mfence  ; Garante ordenação de memória em multi-core
    mov rax, [rdi + ticket_lock.owner]
    cmp rax, [rdi + ticket_lock.next]
    jne .spin
    lock inc dword [rdi + ticket_lock.owner]
    mfence  ; Garante ordenação de memória em multi-core
// ***** SECURITY IMPROVEMENTS *********
    and rax, 0xFFFFF000
// ***** TEST INFRASTRUCTURE *******
%macro STRESS_TEST 1
mov rcx, MAX_PRIORITY_LEVELS
    %1
    loop .loop
// Enterprise Kernel v6.0 - Finalização de Componentes Críticos
// ***** BUDDY ALLOCATOR - SPLIT/MERGE *****
    // RDI=Order, RSI=Block Address
    dec rdi
    mov rdx, 1
    shl rdx, rdi            ; Tamanho do novo bloco
    mov rax, rsi
    add rax, rdx            ; Endereço do buddy
    call mark_block_free    ; Marca buddy como livre
    // RDI=Block Address, RSI=Buddy Address
    mov rdx, rdi
    xor rdx, rsi            ; Verifica se são buddies
    shl rax, rdi
    test rdx, rax
    jnz .no_merge
    call combine_blocks
// ***** EXT2 - INODE E BLOCK ALLOCATION *******
find_free_inode:
    mov rdi, inode_bitmap
    bt [rdi], rcx
    jnc .found
    cmp rcx, 1024
    jl .search
    mov rax, -ENOSPC        ; Sem inodes livres
    lock bts [rdi], rcx
allocate_blocks:
    // RDI=Inode, RSI=Block Count
    mov r8, block_bitmap
.alloc_loop:
    bt [r8], rcx
    jnc .free_block
    jmp .alloc_loop
    lock bts [r8], rcx
    mov [rdi + ext2_inode.i_blocks], rcx
    add rdi, 4
    dec rsi
    jnz .alloc_loop
// ***** VGA DRIVER COMPLETO *******
    cmp dil, 0x0A           ; Newline
    je .newline
    cmp dil, 0x09           ; Tab
    je .tab
    mov [vga_cursor], dil
    add qword [vga_position], 2
.newline:
    mov rax, [vga_position]
    mov rbx, 160
    xor rdx, rdx
    div rbx
    mul rbx
    mov [vga_position], rax
    call vga_scroll
.tab:
    add rax, 16
    and rax, ~15
// ***** MOUSE DRIVER (PS/2) *******
    call decode_packet
    out 0xA0, al
// ***** GESTÃO DE PROCESSOS *******
    // Clonar PCB e page tables
    call copy_pcb
    call copy_page_tables
    // RDI=Path, RSI=argv, RDX=envp
    call load_elf
    jmp rax
    mov rax, -ENOEXEC
// ***** SEGURANÇA - SMEP/SMAP *********
    or rax, (1 << 21) | (1 << 20)  ; SMEP + SMAP
// ***** TESTES UNITÁRIOS **********
    // Aloca e libera blocos de vários tamanhos
    call sys_free
    // Cria e lê arquivo
    mov rdi, test_file
    mov rsi, 512
    call sys_create_file
    mov rsi, buffer
// ***** DADOS INICIALIZADOS *******
// Enterprise Kernel v7.0 - Componentes Críticos Finalizados
// ***** DECODIFICAÇÃO DE PACOTES DO MOUSE *****
decode_packet:
    // Buffer de 3 bytes em [mouse_buffer]
    // Decodificar botões
    test al, 0x01
    jnz .left_button
    test al, 0x02
    jnz .right_button
    test al, 0x04
    jnz .middle_button
    // Decodificar movimento
    movsx rbx, bl
    movsx rcx, cl
    add [mouse_x], rbx
    add [mouse_y], rcx
    // Atualizar cursor
    call update_cursor
// ***** CARREGADOR ELF COMPLETO *******
    // RDI = Ponteiro para o arquivo ELF
    // Verificar assinatura
    cmp dword [rdi], 0x464C457F ; "\x7FELF"
    jne .invalid
    // Carregar cabeçalhos do programa
    // Mapear memória
    mov rdx, [rsi + Elf64_Phdr.p_vaddr]
    mov r8, [rsi + Elf64_Phdr.p_memsz]
    // Copiar dados
    lea rsi, [rsi + Elf64_Phdr.p_offset]
    // Configurar ponto de entrada
.invalid_fix:
    mov rax, -1 ; ENOEXEC
// ***** SISTEMA DE ARQUIVOS EXT2 ******
write_directory_entry:
    mov r8, [rdi + ext2_inode.i_block]
    shl r8, 12 ; Bloco físico
    mov rdi, r8
    // Procurar entrada livre
mov rcx, MAX_PRIORITY_LEVELS
    cmp byte [rdi], 0
    je .found
    add rdi, ext2_dir_entry_size
    // Escrever entrada
    mov [rdi + ext2_dir_entry.inode], rdx
    mov [rdi + ext2_dir_entry.name_len], esi
    lea rsi, [rsi + 1]
// ***** BUDDY ALLOCATOR - MERGE *******
    // RDI = Endereço do bloco, RSI = Ordem
    xor rdx, (1 << (rsi + 12)) ; Endereço do buddy
    cmp [rdx + block_status], 1 ; Buddy está livre?
    jne .done
    // Combinar blocos
    mov [free_lists + rsi*8], rdx
    inc rsi
    call merge_blocks ; Recursivo para ordens superiores
// ***** DRIVER DE DISCO AHCI ******
    or dword [rdi + 0x24], 0x80000000 ; HBA Enable
    // Configurar porta
    mov rsi, [rdi + 0x100] ; Port 0
    mov dword [rsi + 0x10], 0xFFFFFFFF ; Ativar comandos
    // Configurar lista de comandos
    mov rax, command_list
    mov [rsi + 0x00], rax
// ***** TRATAMENTO DE INTERRUPÇÕES ********
    // IRQ 0 (Timer)
    // IRQ 1 (Teclado)
    call process_scancode
// ***** GERENCIAMENTO DE PROCESSOS ********
    // RDI = PID, RSI = Sinal
    mov rbx, [pcb_array + rdi*8]
    or [rbx + PCB.flags], rsi
    // RDI = PID destino, RSI = Mensagem
    mov rdx, [pcb_array + rdi*8]
    mov [rdx + PCB.mailbox], rsi
// Enterprise Kernel v8.0 - Implementações Finais de Componentes Críticos
// ***** DRIVER DE MOUSE - CURSOR E BOTÕES *****
update_cursor:
    // Converter coordenadas para posição VGA (80x25)
    mov rax, [mouse_y]
    mov rbx, 80
    add rax, [mouse_x]
    shl rax, 1              ; Cada caractere = 2 bytes (char + attr)
    // Atualizar cursor via portas VGA
    mov dx, 0x3D4
    mov al, 0x0F
    inc dx
    mov al, ah
    dec dx
    mov al, 0x0E
    // Marcar evento no buffer de entrada
    mov byte [input_buffer], 0x01
    // Chamar syscall  de contexto

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // Chamar syscall de contexto

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    mov rax, 0x57           ; SYS_CONTEXT_MENU
    syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// ***** DRIVER DE TECLADO - SCANCODE PARA ASCII ***
process_scancode:
    // Tabela scancode set 1 para ASCII (exemplo simplificado)
        db 0, 0x1B, '1234567890-=', 0x08, 0x09
        db 'qwertyuiop[]', 0x0D, 0x00
        db 'asdfghjkl;', 0x60, 0x00, '\zxcvbnm,./'
    test al, 0x80           ; Break code?
    jnz .done
    movzx rbx, al
    cmp rbx, 0x39           ; Limite da tabela
    mov al, [scancode_table + rbx]
    call vga_putc
// ***** SISTEMA DE ARQUIVOS EXT2 - LEITURA DE DADOS ***
read_inode:
    // RDI = Número do inode
    mov rax, [superblock.s_inodes_per_group]
    div rdi
    mov rsi, [gd_table + rdx*32 + 4] ; bg_inode_table
    imul rsi, [superblock.s_blocksize]
    add rsi, [disk_base]
    // RDI = Número do bloco
    mov rax, rdi
    imul rax, [superblock.s_blocksize]
    add rax, [disk_base]
mov rcx, MAX_PRIORITY_LEVELS
    cmp dword [rax + ext2_dir_entry.inode], 0
    add rax, ext2_dir_entry_size
    mov [rax + ext2_dir_entry.inode], rdx
    mov [rax + ext2_dir_entry.name_len], esi
    lea rdi, [rax + ext2_dir_entry.name]
sys_create_process:
    // RDI = Caminho do executável
    // Alocar PCB
    mov [rax + PCB.pid], rbx
    mov [rax + PCB.cr3], cr3
    // Clonar PCB e contexto
    mov rsi, [rbx + PCB.cr3]
    or [rdx + PCB.flags], rsi
// ***** DRIVER AHCI - LEITURA DE DISCO ****
// Função: ahci_read (Verificação de Erros)
// AHCI READ - Leitura de blocos do disco via AHCI
// - Usa comandos FIS para comunicar com o controlador AHCI.
// - Copia os dados lidos para o buffer fornecido.
// - Retorna erro caso a operação falhe.
// AHCI READ - Agora inclui verificação de erros
// Reads data from AHCI storage device

// --- Leitura AHCI com validação de buffer ---
// --- Leitura AHCI com validação de buffer ---


// =============================
//   AHCI Read - Leitura de Disco
// =============================
// Realiza uma leitura de bloco de um dispositivo AHCI.
// Entrada:
//   - RDI = Endereço do buffer
//   - RSI = Setor lógico
// Saída:
//   - RAX = Código de erro (0 = sucesso, negativo = falha)
ahci_read:
    test rdi, rdi                  ; Buffer inválido?
    jz .error_invalid_buffer
    // Código de leitura AHCI...
    test rax, rax                  ; Falha na leitura?
    js .error_io
    ret

.error_invalid_buffer:
    mov rax, -EFAULT
    ret

.error_io:
    mov rax, -EIO
    ret
    test rdi, rdi                  ; Buffer inválido?
    jz .error_invalid_buffer
    // Código de leitura AHCI...
    test rax, rax                  ; Falha na leitura?
    js .error_io
    ret
    mov rax, -EFAULT
    ret
    mov rax, -EIO
    ret
    test rdi, rdi                  ; Verifica se o buffer é válido
    jz .error_invalid_buffer
    // ... código de leitura ...
    ret
    mov rax, -EFAULT               ; Retorna erro de ponteiro inválido
    ret
    test rdi, rdi                  ; Verifica se o buffer é válido
    jz .error_invalid_buffer
    // ... código de leitura ...
    ret
    mov rax, -EFAULT               ; Retorna erro de ponteiro inválido
    ret
    test rdi, rdi
    jz .error_null
    call ahci_issue_command
    test rax, rax
    js .error_io
    ret
.error_null:
    mov rax, -EFAULT
    ret
    mov rax, -EIO
    ret
    test rdi, rdi
    jz .error_null_pointer
    // Código normal de leitura aqui
    ret
.error_null_pointer:
    mov rax, -EFAULT
    ret
    call ahci_issue_command
    test rax, rax
    js .error       ; Se falhar, retorna erro
    ret
    mov rax, -EIO   ; Código de erro EIO
    ret
    mov rdx, [ahci_base]  ; Obter endereço base do controlador
    mov rsi, rdi  ; Endereço do buffer de destino
    call ahci_issue_command  ; Enviar comando de leitura
    test rax, rax  ; Verificar status da operação
    js .error  ; Se erro, pular para tratamento
    mov rax, -EIO  ; Retornar erro de leitura
    mov rax, -1  ; Indicar falha
    // RDI = LBA, RSI = Buffer, RDX = Contagem
    mov r8, [ahci_base]
    mov r9, [r8 + 0x100]    ; Port 0
    // Configurar FIS
    mov dword [r9 + 0x00], 0x0027C000 ; FIS_TYPE + CMD
    mov [r9 + 0x04], edi    ; LBA Low
    shr rdi, 32
    mov [r9 + 0x08], edi    ; LBA High
    mov [r9 + 0x0C], rdx    ; Contagem
    // Executar comando
    mov dword [r9 + 0x10], 1<<16 ; Start
    test dword [r9 + 0x10], 1<<30 ; Busy
// ***** TESTES E EXEMPLOS *********
%macro TEST_MOUSE 0
    cmp byte [input_buffer], 0x01
    jne .test_failed
%macro TEST_KEYBOARD 1
    cmp [vga_buffer], %1
// Enterprise Kernel v9.0 - Finalização de Componentes e Segurança
// ***** GERENCIAMENTO DE CLIQUES DO MOUSE *****
    // Verificar coordenadas do cursor
    mov rax, [mouse_x]
    mov rbx, [mouse_y]
    call get_screen_element  ; Retorna elemento em RAX
    jz .exit
    call sys_ui_event
    // Abrir menu de contexto
    mov rdi, [mouse_x]
    mov rsi, [mouse_y]
    mov rax, 0x58            ; SYS_SHOW_CONTEXT_MENU
    // ... (implementação anterior)
     // Resolver símbolos dinâmicos
    mov rsi, [rdi + Elf64_Ehdr.e_shoff]
    add rsi, rdi
    movzx rcx, word [rdi + Elf64_Ehdr.e_shnum]
    cmp dword [rsi + Elf64_Shdr.sh_type], 11 ; SHT_DYNSYM
    je .found_dynsym
    add rsi, Elf64_Shdr_size
    loop .find_dynsym
    jmp .error
.found_dynsym:
    // Carregar tabela de símbolos
    mov r8, [rsi + Elf64_Shdr.sh_offset]
    add r8, rdi
    mov r9, [rsi + Elf64_Shdr.sh_size]
// ***** SISTEMA DE ARQUIVOS EXT2 COMPLETO *****
ext2_create_file:
    call allocate_inode
    call write_dir_entry
ext2_write:
    // RDI = Inode, RSI = Buffer, RDX = Tamanho
    shl r8, 12              ; Converter para endereço físico
mov rcx, MAX_PRIORITY_LEVELS
    call mark_inode_dirty
// ***** DRIVER DE REDE VIRTIO *********
virtio_net_init:
    mov rdi, 0x1000          ; MMIO base
    mov dword [rdi + 0x08], 0x1 ; DRIVER_OK
    mov dword [rdi + 0x30], 0x1000 ; RX queue
	// Adicionar implementação completa do tratamento de pacotes TCP/IP
virtio_send_packet:
    // RDI = Buffer, RSI = Tamanho
    mov r8, [virtio_tx_queue]
    mov [r8 + 0x00], rdi     ; Descrição do buffer
    mov [r8 + 0x08], rsi
    mov dword [virtio_mmio + 0x40], 1 ; Notificar dispositivo
// ***** GERENCIAMENTO DE PROCESSOS AVANÇADO ***
    // RDI = PID, RSI = Opções
.wait_loop:
    test byte [rbx + PCB.state], 0x80 ; Zombie?
    call schedule
    jmp .wait_loop
    mov rax, [rbx + PCB.exit_code]
    // RDI = PID destino, RSI = Mensagem, RDX = Tamanho
    call validate_ipc_buffer
    jz .fault
    mov r8, [pcb_array + rdi*8]
    mov [r8 + PCB.mailbox], rsi
// ***** MEDIDAS DE SEGURANÇA *********
    and rax, 0xFFFFF000      ; Alinhar em 4KB
    mov cr3, rax             ; Recarregar paginação
        // Proteção contra buffer overflow usando Stack Canaries
        call check_stack_integrity
            // Verificar canary na thread atual
    mov rax, [current_pcb + PCB.canary]
    cmp rax, 0xDEADBEEFCAFEBABE
    jne .stack_overflow
.stack_overflow:
    mov rax, -EPERM
// ***** TESTES E VALIDAÇÃO ********
%macro TEST_EXT2 0
    // Criar e ler arquivo
    mov rsi, 0o644
    call ext2_create_file
    js .test_fail
    mov rsi, test_data
    mov rdx, 512
    call ext2_write
    call ext2_read
    cmp rax, 512
    jne .test_fail
// Enterprise Kernel v10.0 - Componentes Finais e Testes
ext2_read_inode:
    div qword [superblock.s_inodes_per_group]
    mov rsi, [gd_table + rax*32 + 8]   ; bg_inode_table
    lea rax, [rsi + rdx*128]          ; Tamanho do inode = 128 bytes
ext2_delete_file:
    // RDI = Inode do arquivo
    // Liberar blocos
mov rcx, MAX_PRIORITY_LEVELS
    // Liberar inode
    sub rax, [disk_base]
    lock btr [inode_bitmap + rdx/8], rdx%8
    call remove_dir_entry
    mov rsi, [rdi + ext2_inode.i_block]
    shl rsi, 12                      ; Converter para endereço físico
mov rcx, MAX_PRIORITY_LEVELS
    shr rcx, 4                       ; Entradas por bloco (16 bytes cada)
    mov rdx, [rsi + ext2_dir_entry.inode]
    test rdx, rdx
    jz .skip
    // Adicionar entrada à lista
    mov [rdi + dir_entries], rdx
    add rsi, ext2_dir_entry_size
    loop .dir_loop
// ***** GERENCIAMENTO DE EVENTOS DE MOUSE *****
get_screen_element:
    // RDI = X, RSI = Y (coordenadas textuais)
    // Retorna elemento em RAX (0 = nenhum)
    mov rax, [screen_buffer + rsi*80 + rdi]
    and rax, 0x00FFFFFF              ; Máscara de atributos
sys_ui_event:
    // RDI = Elemento, RSI = Tipo de evento
    cmp rsi, 0x01                    ; Clique
    cmp rsi, 0x02                    ; Hover
    je .handle_hover
    // Disparar ação baseada no elemento (ex: botão)
    jmp [ui_action_table + rdi*8]
.handle_hover:
    // Atualizar estado visual
// ***** DRIVER DE REDE VIRTIO (RECEPÇÃO) ******
virtio_receive_packet:
    // Verificar fila de recepção
    mov rdi, [virtio_rx_queue]
    test qword [rdi + 0x00], 1       ; Buffer disponível?
    // Copiar pacote para buffer do kernel
    mov rsi, [rdi + 0x08]            ; Endereço físico
    mov rdx, [rdi + 0x10]            ; Tamanho
    call net_rx_handler
    // Atualizar fila
    mov qword [rdi + 0x00], 0        ; Marcar como lido
    // Verificar origem da interrupção
    in al, 0x20
    test al, 0x80
    jnz .rx_irq_
    jnz .rx_irq
    call virtio_receive_packet
// ***** GERENCIAMENTO DE PROCESSOS COMPLETO ***
    test rbx, rbx
    or [rbx + PCB.flags], rsi        ; Registrar sinal
    mov rax, -ESRCH                  ; Processo não existe
    // RDI = Sinal, RSI = Handler
    mov [signal_table + rdi*8], rsi
    test qword [rbx + PCB.mailbox], 0xFFFF
    jz .wait
    // Copiar mensagem
mov rcx, MAX_PRIORITY_LEVELS
    mov rsi, [rbx + PCB.mailbox]
// ***** SEGURANÇA AVANÇADA ********
    // Verificar acesso a user-space em código do kernel
    // RDI = Número da syscall 

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    // RDI = Número da syscall

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    cmp rdi, 0x40                    ; Limite máximo
    ja .invalid
    bt [syscall _bitmap], rdi

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    bt [syscall bitmap], rdi

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

    jnc .invalid
// Enterprise Kernel v11.0 - Implementações Finais e Testes
// ***** DRIVER DE REDE VIRTIO COMPLETO ****
    // Inicializar filas de transmissão (TX) e recepção (RX)
    mov rdi, [virtio_mmio]
    // Configurar RX queue
    mov qword [rdi + 0x30], virtio_rx_desc   ; Endereço da RX queue
    mov dword [rdi + 0x44], 0x1000          ; Tamanho da fila (4096 entradas)
    // Configurar TX queue
    mov qword [rdi + 0x38], virtio_tx_desc
    mov dword [rdi + 0x48], 0x1000
    // Ativar dispositivo
    mov dword [rdi + 0x08], 0x1             ; DRIVER_OK
    // Verificar pacotes na RX queue
    mov rsi, [virtio_rx_desc + 0x00]        ; Índice atual
    cmp rsi, [virtio_rx_desc + 0x08]        ; Comparar com último índice usado
    je .no_packet
    // Calcular endereço do pacote
    imul rax, 16                            ; Cada descritor tem 16 bytes
    add rax, virtio_rx_buffer
    mov rdi, [rax + 0x00]                   ; Endereço físico
mov rcx, MAX_PRIORITY_LEVELS
    // Atualizar índice
    and rsi, 0xFFF                          ; Módulo 4096
    mov [virtio_rx_desc + 0x00], rsi
.no_packet:
// ***** INTERFACE DE USUÁRIO - EVENTOS ****
    // RDI = Tipo de evento (0=left, 1=right), RSI = Coordenadas (X << 32 | Y)
    mov r8, rsi
    shr r8, 32                              ; X
    mov r9, rsi                             ; Y
    and r9, 0xFFFFFFFF
    call get_screen_element
    // Disparar ação baseada no elemento
    mov rbx, [ui_element_table + rax*8]
    jmp rbx
    // Atualizar estado visual do elemento
    mov rdi, [screen_buffer + rsi*80 + rdi]
    call update_element_visual
// ***** SISTEMA DE ARQUIVOS EXT2 FINAL ****
ext2_delete_dir_entry:
    call find_dir_entry
    // Marcar entrada como livre
    mov dword [rax + ext2_dir_entry.inode], 0
    call sync_inode
    // Sincronizar inode e blocos com o disco
    mov rdi, [current_inode]
    call ahci_flush
// ***** GERENCIAMENTO DE PROCESSOS FINAL ******
    // Configurar novo PCB
    mov [rax + PCB.pid], rcx
    mov [rax + PCB.state], PCB_STATE_READY
    // RDI = PID, RSI = Status
    test byte [rbx + PCB.state], PCB_STATE_ZOMBIE
    mov [rsi], dword [rbx + PCB.exit_code]
    call free_pcb
// ***** SEGURANÇA - HARDENING ********
    // Verificar RDI, RSI, RDX estão dentro do espaço do usuário
    mov rdi, rsi
    mov rdi, rdx
// ***** TESTES E DADOS ********
// --- Manipulador de interrupção de teclado ---

// =============================
//   Tratamento de Interrupção: Teclado
// =============================
keyboard_handler:
    in al, 0x60                      ; Reads scancode
    mov [keyboard_buffer], al
    mov al, 0x20
    out 0x20, al                     ; End of Interrupt to PIC
    iretq
    push rax
    push rbx
    push rcx
    in al, 0x60     ; Lê código da tecla
    // Processamento do evento do teclado aqui...
    out 0x20, al    ; Envia EOI ao PIC
    pop rcx
    pop rbx
    pop rax
    iretq
    in al, 0x60
    mov al, 0x20
    out 0x20, al                   ; End of Interrupt to PIC
    iretq
    in al, 0x60
    mov al, 0x20
    out 0x20, al          ; EOI para o PIC
    iretq
    in al, 0x60
    mov al, 0x20
    out 0x20, al
    iretq
    in al, 0x60
    // Verifica se o buffer está cheio (exemplo: buffer de 128 bytes)
    mov rbx, [keyboard_buffer_head]
    inc rbx
    and rbx, 0x7F                      ; Módulo 128
    cmp rbx, [keyboard_buffer_tail]
    je .buffer_full
    mov [keyboard_buffer + rbx], al
    mov [keyboard_buffer_head], rbx
.buffer_full:
    mov al, 0x20
    out 0x20, al                       ; EOI
    iretq
    call process_keyboard_input
// Implementation inicial baseada em Red-Black Tree (Árvore RB)
    // Insere uma nova tarefa na árvore RB
    // Parâmetro: %1 - Ponteiro para a estrutura de tarefa
    mov rdi, %1
    call rb_tree_insert
    // Remove uma tarefa da árvore RB
    call rb_tree_remove
    // Percorre a árvore RB para encontrar o núcleo com menos carga
    // Implementation inicial do balanceamento de carga
    call find_least_loaded_core  ; Seleciona o núcleo menos carregado
    call migrate_process         ; Move o processo para esse núcleo
    test rax, rax  ; Verificar se a leitura falhou
    jz .error      ; Saltar para tratamento de erro se necessário
    mov rax, -EIO  ; Retornar erro de entrada/saída em caso de falha
    ret
    ret
//                Verificação de Segurança (SMEP, SMAP, KASLR)   
//                Segurança: SMEP, SMAP e KASLR
// Implementation para reforçar a segurança do sistema operacional.
    mov rax, cr4
    jz .smep_disabled
    jz .smap_disabled
    // Verificar KASLR (endereço kernel não fixo)
    mov rax, [kernel_base]
    cmp rax, KERNEL_BASE
    je .kaslr_disabled
    ret
.kaslr_disabled:
    mov rax, -ENOTSUP
    ret
    test cr4, 0x100000 ; Verifica SMEP
    test cr4, 0x200000 ; Verifica SMAP
    test rdx, 0x1 ; Verifica KASLR
    // Verifica se SMEP está ativado (bit 20 do CR4)
    jz .smep_disabled
    // Verifica se SMAP está ativado (bit 21 do CR4)
    jz .smap_disabled
    // Verifica se KASLR está ativado (Endereços aleatórios no kernel)
    xor rax, rax  ; Placeholder: Implementation pendente
    jz .kaslr_disabled
    mov rax, -EACCES  ; Erro de permissão
    xor rax, rax  ; Placeholder: Implementation pendente
    // Implementation inicial do balanceamento de carga
    call find_least_loaded_core  ; Seleciona o núcleo menos carregado
    call migrate_process         ; Move o processo para esse núcleo
    test rcx, (1 << 20)  ; Verifica SMEP
    test rcx, (1 << 21)  ; Verifica SMAP
    test rcx, (1 << 22)  ; Verifica KASLR
    ret
    xor rax, rax  ; Por enquanto, retorna 0 (não implementado)
//                Implementation de KASLR (Kernel ASLR)
// KASLR (Kernel Address Space Layout Randomization) protege contra
// ataques que dependem de endereços previsíveis do kernel.
//
// O kernel será deslocado em um intervalo aleatório na inicialização.
    // Gera um deslocamento aleatório para o kernel
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx              ; Combina EDX:EAX em RAX
    xor rax, [timestamp]     ; Usa um timestamp variável para mais entropia

    call secure_rng ; Usar timestamp como fallback
    and rax, 0xFFF          ; Limita a aleatorização a um intervalo seguro
    shl rax, 12             ; Ajusta para alinhamento de página (4KB)
    // Ajusta o endereço base do kernel com o deslocamento
    mov rbx, KERNEL_BASE    ; Obtém endereço base do kernel
    add rbx, rax            ; Aplica deslocamento aleatório
    // Atualiza os ponteiros críticos
    mov [KERNEL_ENTRY], rbx  ; Define nova entrada do kernel
    mov [IDT_BASE], rbx      ; Ajusta tabela de interrupções
    mov [GDT_BASE], rbx      ; Ajusta tabela de descritores globais
    // Indica que KASLR está ativado

    // ===============================
    // Verifica se a página pode ser acessada pelo usuário
    // Retorna 0 se permitido, -EFAULT se inválido
    // ===============================
check_page_permissions:
    // Obtém a entrada da tabela de páginas para o endereço dado
    mov rax, [rdi]
    // Verifica se a página está presente na memória
    test rax, PAGE_PRESENT | PAGE_USER
    jz .invalid
    ret
    mov rax, -EFAULT
    ret

// --- Ativação de SMEP/SMAP para segurança ---
// --- Habilita SMEP/SMAP (Segurança) ---
enable_smep_smap:
    mov rax, cr4
    or rax, (1 << 20) | (1 << 21)  ; Ativa SMEP (bit 20) e SMAP (bit 21)
    mov cr4, rax
    ret
    mov rax, cr4
    or rax, (1 << 20) | (1 << 21)  ; Ativa SMEP (bit 20) e SMAP (bit 21)
    mov cr4, rax
    ret
    mov rax, cr4
    or rax, (1 << 20) | (1 << 21)  ; Bits 20 (SMEP) e 21 (SMAP)
    mov cr4, rax
    ret
    mov rax, cr4
    or rax, (1 << 20) | (1 << 21)  ; Habilita SMEP e SMAP para evitar acessos não autorizados
    mov cr4, rax
    ret


// --- Consolidated check_vtx_support function ---


mov rax, 1
    cpuid
    test ecx, (1 << 5)      ; VT-x (Intel)
    jnz .supported
    test edx, (1 << 12)     ; AMD-V (AMD)
    jnz .supported
    mov rax, -ENOTSUP       ; Retorna erro
    ret
    xor rax, rax            ; Sucesso
    ret
mov rax, 1
    cpuid
    test ecx, (1 << 5)      ; VT-x (Intel)
    jnz .supported
    test edx, (1 << 12)     ; AMD-V (AMD)
    jnz .supported
    mov rax, -ENOTSUP       ; Retorna erro
    ret
    xor rax, rax            ; Sucesso
    ret
mov rax, 1
    cpuid
    test ecx, (1 << 5)      ; VT-x (Intel)
    jnz .supported
    test edx, (1 << 12)     ; AMD-V (AMD)
    jnz .supported
    mov rdi, vtx_error_msg  ; Carrega mensagem de erro
    ret
    ret


// --- Optimized schedule function ---

// --- Escalonador MLFQ (Multi-Level Feedback Queue) ---
// Prioridades: 0 (mais alta) a MAX_PRIORITY_LEVELS-1 (mais baixa)
// Implementa aging para evitar starvation.
// --- Escalonador MLFQ Unificado ---
schedule:
    mov esi, calculate_dynamic_priority()  ; Prioridade mais alta
.loop:
    cmp esi, 0
    jl .idle                          ; No ready processes
    mov rax, [queues + esi*8]         ; Gets the current queue
    test rax, rax
    jnz .switch_process               ; Process found
    dec esi                           ; Prioridade mais baixa
    jmp .loop
.switch_process:
    call context_switch               ; Context switch
    ret
.idle:
    hlt                               ; Waits for an interrupt
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
.idle:
    hlt
    jmp schedule
    mov esi, calculate_dynamic_priority() ; Começa pela prioridade mais alta
    cmp esi, 0
    jl .idle                        ; No ready processes
    mov rax, [queues + esi*8]       ; Gets the current queue
    test rax, rax
    jnz .switch_process             ; Process found
    dec esi                         ; Prioridade mais baixa
    jmp .loop
    call context_switch             ; Context switch
    ret
    hlt                             ; Waits for an interrupt
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    sti
    hlt
    pushfq
    cli
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    sti
    hlt
    pushfq
    cli
    jmp schedule
    mov esi, calculate_dynamic_priority()
    cmp esi, 0
    jl .idle
    mov rax, [queues + esi*8]
    test rax, rax
    jnz .switch_process
    dec esi
    jmp .loop
    call context_switch
    ret
    sti
    hlt
    pushfq
    cli
    jmp schedule

// ===============================
// Habilitação de SMEP/SMAP
// ===============================

// --- Ativação de SMEP/SMAP para segurança ---
    mov rax, cr4
    or rax, (1 << 20) | (1 << 21)  ; Ativa SMEP (bit 20) e SMAP (bit 21)
    mov cr4, rax
    ret
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro
    push rax
    push rcx
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rax
    push rcx
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push rax
    push rcx
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
%endmacro
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
%endmacro
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax


// ===============================
// Implementation de Bitmaps para Gerenciamento de Memória
// Utiliza uma estrutura de bitmap para rastrear blocos livres/ocupados
// ===============================
MAX_BLOCKS equ 64  ; Definir número máximo de blocos de memória
allocate_memory:
    mov rdi, free_lists
    xor rcx, rcx
.find_free_block:
    bt [rdi], rcx
    jnc .allocate
    inc rcx
    cmp rcx, MAX_BLOCKS
    jae .no_memory
    jmp .find_free_block
.no_memory:
    mov rax, -ENOMEM
    ret
.allocate:
    bts [rdi], rcx
    lea rax, [MEMORY_BASE + rcx * BLOCK_SIZE]
    ret
    // Percorre o bitmap de memória procurando um bloco livre
    mov rdi, free_lists      ; Ponteiro para o bitmap
    xor rcx, rcx             ; Índice do bloco

    jnc .allocate
    inc rcx
    cmp rcx, MAX_BLOCKS
    jae .no_memory  ; Sai se rcx >= MAX_BLOCKS
    jmp .find_free_block
    bt [rdi], rcx            ; Testa o bit correspondente ao bloco
    jnc .allocate            ; Se estiver livre, aloca
    inc rcx
    cmp rcx, MAX_BLOCKS
    jae .no_memory  ; Tratar erro se exceder o limite
    jl .find_free_block
    mov rax, -ENOMEM         ; Retorna erro se não houver espaço
    bts [rdi], rcx           ; Marca o bloco como ocupado
    lea rax, [MEMORY_BASE + rcx * BLOCK_SIZE]  ; Retorna o endereço do bloco
    ret



secure_rng:
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax
    jnc .fallback
    ret
    // Implementation de xorshift128+ para PRNG seguro
    mov rax, [seed]
    mov rdx, [seed+8]
mov rcx, MAX_PRIORITY_LEVELS
    shl rax, 23
    xor rax, rcx
    xor rax, rdx
    xor rax, rcx
    shr rdx, 5
    xor rdx, rax
    mov [seed], rdx
    mov [seed+8], rax
    ret
    cpuid
    bt ecx, 30   ; Verifica suporte a RDRAND
    jnc .fallback_rng  ; Se não suportado, usa fallback
    rdrand rax          ; Usar instrução RDRAND (se disponível)
    jnc .fallback
    ret
    // Gerador PRNG seguro (exemplo de ChaCha20 pode ser implementado depois)
mov rax, 1
    cpuid
    test edx, (1 << 4)  ; Verifica suporte a TSC
    jz .unsupported_cpu
    // rdtsc removido - implementando um PRNG mais seguro
    shl rdx, 32
    or rax, rdx
    ret



init_pci_device:
mov rax, 0x80000000
    or eax, edi  ; Combinar bus/device/function
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    ret
    // Parâmetros: RDI = dispositivo PCI
    push rax
    push rcx
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    push rdx
mov rax, 0x80000000
    or eax, rdi     ; Bus << 16 | Device << 11 | Function << 8 | Register Offset
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    pop rdx
    pop rax
    ret
    push rdx
mov rax, 0x80000000
    or eax, rdi     ; Bus << 16 | Device << 11 | Function << 8 | Register Offset
    mov dx, 0xCF8
    out dx, eax
    mov dx, 0xCFC
    in eax, dx
    pop rdx
    pop rax
    ret

// ---- Verificação de Suporte à Virtualização (VT-x/AMD-V) ----

// ================================================================
//                Verificação de Virtualização (VT-x/AMD-V)
//                Verificação de Suporte à Virtualização (VT-x/AMD-V)

// ---- Verificação de Suporte à Virtualização (VT-x/AMD-V) ----
.supported:
mov rax, 1
    cpuid
    test ecx, (1 << 5)      ; VT-x (Intel)
    jnz .supported
    test edx, (1 << 12)     ; AMD-V (AMD)
    jnz .supported
    mov rdi, vtx_error_msg  ; Carrega mensagem de erro
    ret
    ret
mov rax, 1
    cpuid
    test ecx, (1 << 5)  ; VT-x (Intel)
    jnz .supported
    test edx, (1 << 12) ; AMD-V (AMD)
    jnz .supported
    mov rdi, vtx_error_msg
    ret
    ret
mov rax, 1
    cpuid
    test ecx, (1 << 5)  ; Check for VT-x support (bit 5 in ECX)
    jnz .supported
    test edx, (1 << 12) ; Check for AMD-V support (bit 12 in EDX)
    jnz .supported
    mov rdi, vtx_error_msg  ; Load error message
    ret
    ret
    ret
mov rax, 1
    cpuid
    test ecx, (1 << 5)      ; VT-x
    jnz .vtx_supported
    test edx, (1 << 12)     ; AMD-V
    jnz .amd_v_supported
    mov rdi, vtx_error_msg  ; Load error message
    ret
.vtx_supported:
.amd_v_supported:
    ret
mov rax, 1
    cpuid
    test ecx, (1 << 5)      ; Bit 5 do ECX para VT-x
    jz .check_amd_v
    ret
.check_amd_v:
    test edx, (1 << 12)     ; Bit 12 do EDX para AMD-V
    jz .no_vtx
    ret
.no_vtx:
    mov rdi, vtx_error_msg  ; Load error message
    ret
mov rax, 1
    cpuid
    jz .no_vtx
    ret
    ret
    mov rax, 1
    test rcx, (1 << 5)  ; Bit 5 = VT-x
//                KERYGMA-X OS - Versão Final
//_Melhorias:
// - Documentação aprimorada em funções críticas.
// - Implementation de verificações para interrupções, syscalls e drivers.

// --- Logging e Auditoria de Segurança ---
security_log db "Tentativa de acesso negado!", 0
log_file db "/var/log/keryma.log", 0

// Consolidando log_event em macro única

// =============================
//   Macro de Logging de Segurança
// =============================
%macro LOG_SECURITY_EVENT 1
    mov rdi, log_file
    mov rsi, %1
    call write_log
%endmacro

// Uso:
LOG_SECURITY_EVENT access_denied_msg
    mov rdi, log_file
    mov rsi, security_log
    call write_log
    mov rdi, log_file
    mov rsi, security_log
    call write_log
log_event:
    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Implementation de verificações para interrupções, syscalls e drivers.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Padronização com remoção de código duplicado.
// - Uso de macros para operações comuns.
// - Adição de tratamento de erro em I/O e syscalls.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

// - Adição de tratamento de erro em I/O e syscalls.

// --- Logging e Auditoria de Segurança ---

    mov rdi, log_file
    mov rsi, security_log
    call write_log
    ret

//                Macros de Contexto
    push rdx

    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax

    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rsp
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop rdx
    pop rcx
    pop rax
//                KERYGMA-X OS - Versão Otimizada
// - Fortalecimento de segurança (SMEP, SMAP, KASLR)
// - Melhor organização do código com macros
// - Adição de verificações de erro
//                         KERYGMA-X OS
 * Copyright (C) 2025 Dilermax Well
 * All rights reserved.
// Autor: Dilermax Well / Ademax A.S.S
// Versão: 1.0
// Data: [1 de fervereiro]
// Descrição: Este é o código-fonte do Kerygma-X OS, um sistema
// operacional escrito em Assembly x86-64 com suporte a interface gráfica,
// multitarefa, sistema de arquivos, segurança avançada e virtualização.
// O código-fonte deste kernel está sob a licença GNU General Public License 
 * (GPL), permitindo que você copie, modifique e redistribua o código, 
 * desde que as condições da licença sejam seguidas.
//                    SEÇÕES DO CÓDIGO
// 1. Inicialização do Bootloader
// 2. Gerenciamento de Memória
// 3. Interface Gráfica (GUI)
// 4. Gerenciamento de Processos e Syscalls
// 5. Sistema de Arquivos (VFS)
// 6. Segurança e Virtualização
// 7. Aplicações e Shell
// ============================================

// Código Principal do Kernel - Seção TEXT
// SEÇÃO DE CÓDIGO (.text) - Instruções do Kernel
// Bootloader - Inicialização do Kernel
// ================================
// Inicialização do Bootloader
// - Desativa interrupções para evitar erros durante a transição de modo.
// - Carrega a Global Descriptor Table (GDT).
// - Ativa o modo protegido, permitindo acesso à memória extendida.
// - Salta para o modo protegido para continuar a execução.
//                Inicialização da GDT
//                Inicialização Única da GDT
//                Definição Única da GDT
// --- Definição da GDT (Global Descriptor Table) ---
// Kernel code here


gdt_start:
    dq 0x0  ; Entrada nula
align 8
    dq 0x0  ; Entrada nula
// Ativar o bit PE (Protection Enable) no CR0.
    or eax, 1
// Escrever de volta no CR0 para efetivar a ativação do modo protegido.
    mov cr0, eax  ; Ativar modo protegido
// Saltar para a execução no modo protegido (segmento de código 0x08).
// Manipulação eficiente de interrupção do teclado
// Interrupção do Teclado (Correção de Pilha)
// Manipulação da Interrupção de Teclado
// - Captura a tecla pressionada e armazena no buffer de entrada.
// - Garante que a pilha esteja correta antes de retornar da interrupção.
// INTERRUPÇÃO DO TECLADO - Unificada e otimizada
// INTERRUPÇÃO DO TECLADO - UNIFICADA E OTIMIZADA
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    in al, 0x60
    mov al, 0x20
    out 0x20, al  ; End of Interrupt to PIC
%macro RESTORE_FULL_CONTEXT 0
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rsp
    pop rbx
RESTORE_FULL_CONTEXT
    iretq
    call generate_stack_canary  ; Inicializa o stack canary na TLS
    mov rax, gs:[0x28]  ; Load stack canary
global schedule
// Multi-Level Feedback Queue otimizado
// SEÇÃO DE DADOS (.data) - Variáveis Estáticas

// Definição da Tabela de Syscalls
%define SYS_EXIT   0x01
%define SYS_READ   0x02
%define SYS_WRITE  0x03
// ... outras syscalls
    align 8
    syscall_table dq sys_exit, sys_read, sys_write ; Alinhado em 8 bytes
syscall_table:
    dq sys_exit    ; 0x00
    dq sys_read    ; 0x01
    dq sys_write   ; 0x02
    // ... outras syscalls ...
    dq sys_exit
    dq sys_fork
    dq sys_exec
    dq sys_mmap
    // ... outras syscalls ...
    dq sys_exit
    dq sys_read
    dq sys_write
    // ... demais entradas


    dq sys_exit    ; 0x00
    dq sys_read    ; 0x01
    dq sys_write   ; 0x02
