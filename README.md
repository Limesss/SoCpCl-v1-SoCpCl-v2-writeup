Foreword
Originally, the challenge only had v1. However, after the challenge was released, the vulnerability author publicly released a detailed write-up (WP) for it. 
<p> So we urgently added a "SoCpCl v2" challenge. V2 primarily adds a gap memory bypass on top of v1. V2 is another exploit method I discovered while reproducing the vulnerability. 
<p> Of course, by the time I saw the author's WP, I had almost no time to verify if the exploit in the blog could be directly used. However, after my brief testing, it didn't run successfully. Therefore, I cannot completely rule out all unintended solutions here.
refer: [Author Link](https://anatomi.st/blog/2025_06_27_pwning_solana_for_fun_and_profit)

## SoCpCl v1
The specific vulnerability analysis is already very clear in the author's linked article. 
Here, I'll just explain the solutions for these two challenges.
The vulnerability primarily stems from an issue during the update of caller_account. If the mapping corresponding to caller_account's vm_data_addr is inconsistent with the data_ptr corresponding to callee_account, the host for vm_data_addr will be set to data_ptr.
```rust
fn update_caller_account(
    invoke_context: &InvokeContext,
    memory_mapping: &MemoryMapping,
    is_loader_deprecated: bool,
    caller_account: &mut CallerAccount,
    callee_account: &mut BorrowedAccount<'_>,
    direct_mapping: bool,
) -> Result<(), Error> {
				[......]
        let region = memory_mapping.region(AccessType::Load, caller_account.vm_data_addr)?;
        let callee_ptr = callee_account.get_data().as_ptr() as u64;
        if region.host_addr.get() != callee_ptr {
            region.host_addr.set(callee_ptr);
        }
    }
```
Before we proceed, let's first clarify the relationship between vm_data_addr and host_addr within a region. This explanation is excerpted from a presentation.
The image on the left shows two MemoryRegions. [image FROM ppt](https://www.hexacon.fr/slides/Ginoah-pwning_blockchain_for_fun_and_profit.pdf)
![](/img/image.png)




The VM Memory on the right represents the VM created by the validator during process_instruction. Host Memory indicates where data is read from or written to within the validator when performing read/write operations on VM Memory. We can normally read from and write to VM Memory directly, but we can only read from and write to Host Memory through VM Memory.
The caller_account is obtained from accounts, meaning the account_info corresponding to these accounts is retrieved from the caller's VM Memory, which we can directly modify. In contrast, callee_account is one of the borrowed instruction_accounts. It originally exists in Host Memory and cannot be directly modified via the contract.
```rust
let mut accounts = S::translate_accounts(
        &instruction_accounts,
        &program_indices,
        account_infos_addr,
        account_infos_len,
        is_loader_deprecated,
        memory_mapping,
        invoke_context,
    )?;

	  [......]
   
   
    for (index_in_caller, caller_account) in accounts.iter_mut() {
        if let Some(caller_account) = caller_account {
            let mut callee_account = instruction_context
                .try_borrow_instruction_account(transaction_context, *index_in_caller)?;
            update_caller_account(
                invoke_context,
                memory_mapping,
                is_loader_deprecated,
                caller_account,
                &mut callee_account,
                direct_mapping,
            )?;
        }
    }
```
So, the goal is clear: we can use update_caller_account to modify the Host_addr that a vm_data_addr maps to.
```rust
fn update_caller_account(
    invoke_context: &InvokeContext,
    memory_mapping: &MemoryMapping,
    is_loader_deprecated: bool,
    caller_account: &mut CallerAccount,
    callee_account: &mut BorrowedAccount<'_>,
    direct_mapping: bool,
) -> Result<(), Error> {
				[......]
        let region = memory_mapping.region(AccessType::Load, caller_account.vm_data_addr)?;
        let callee_ptr = callee_account.get_data().as_ptr() as u64;
        if region.host_addr.get() != callee_ptr {
            region.host_addr.set(callee_ptr);
        }
    }
```
## SoCpCl v2
```
- let is_loader_deprecated = *instruction_context
-        .try_borrow_last_program_account(transaction_context)?
-        .get_owner()
+ let is_loader_deprecated = false;
```
Here's the main point: in newer versions of Solana, is_loader_deprecated defaults to false. So, this patch serves as a reminder.
Next, we just need to see which parts of the code are affected by changes to is_loader_deprecated.
Ultimately, it's used in from_account_info, primarily influencing the length selection when translating serialized_data. When is_loader_deprecated is false, the length used is MAX_PERMITTED_DATA_INCREASE, which is 0x2800. We need to ensure that when vm_data_addr.saturating_add(original_data_len as u64) is translated to host_addr, it does not fall into gap memory. This is why a different exploit method is used here. For details, please refer to the exploit (Exp).
```rust
fn from_account_info(
    invoke_context: &InvokeContext,
    memory_mapping: &MemoryMapping,
    is_loader_deprecated: bool,
    _vm_addr: u64,
    account_info: &AccountInfo,
    original_data_len: usize,
) -> Result<CallerAccount<'a>, Error> {
    [......]
    let serialized_data = translate_slice_mut::<u8>(
    memory_mapping,
    if bpf_account_data_direct_mapping {
        vm_data_addr.saturating_add(original_data_len as u64)
    } else {
        vm_data_addr
    },
    if bpf_account_data_direct_mapping {
        if is_loader_deprecated {
            0
        } else {
            MAX_PERMITTED_DATA_INCREASE
        }
    } else {
        data.len()
    } as u64,
    invoke_context.get_check_aligned(),
    invoke_context.get_check_size(),
)?;

(
    serialized_data,
    vm_data_addr,
    ref_to_len_in_vm,
    serialized_len_ptr,
)
    };
```
