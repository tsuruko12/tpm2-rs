use std::sync::Once;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use tpm_tool::{Context, Error};

static INIT: Once = Once::new();

#[cfg(target_os = "linux")]
pub(crate) fn connect_tpm() -> Context {
    init_tracing();
    let mut ctx = Context::connect_from_env().expect("failed to connect to swtpm");

    if let Err(e) = ctx.provision() {
        assert!(matches!(e, Error::StoreAlreadyExists));
    }

    ctx
}

#[cfg(target_os = "windows")]
pub(crate) fn connect_tpm() -> Context {
    init_tracing();
    let mut ctx = Context::connect().expect("failed to connect to the TPM");

    if let Err(e) = ctx.provision() {
        assert!(matches!(e, Error::StoreAlreadyExists));
    }

    ctx
}

fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    });
}

#[cfg(target_os = "windows")]
mod persistent_key_cleanup {
    use std::{ffi::c_void, ptr};

    use windows_sys::Win32::System::TpmBaseServices::{
        Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
        TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, TPM_VERSION_20,
    };

    const TPM_ST_SESSIONS: u16 = 0x8002;
    const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
    const TPM_RH_OWNER: u32 = 0x4000_0001;
    const TPM_RS_PW: u32 = 0x4000_0009;
    const TPM_RC_OBJECT_HANDLE_NOT_FOUND: u32 = 0x0000_018B;
    const RESPONSE_BUFFER_SIZE: usize = 256 * 1024;

    const CREATED_PERSISTENT_HANDLES: [u32; 4] =
        [0x8100_0003, 0x8100_0004, 0x8100_8001, 0x8100_8002];

    struct TbsContext(*mut c_void);

    impl Drop for TbsContext {
        fn drop(&mut self) {
            unsafe { Tbsip_Context_Close(self.0) };
        }
    }

    fn create_tbs_context() -> TbsContext {
        let params = TBS_CONTEXT_PARAMS2 {
            version: TPM_VERSION_20,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 4 },
        };
        let mut handle = ptr::null_mut();

        let status = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle,
            )
        };
        assert_eq!(
            status, TBS_SUCCESS,
            "failed to create TBS context: {status:#010X}"
        );

        TbsContext(handle)
    }

    fn evict_control_command(handle: u32) -> Vec<u8> {
        let mut command = Vec::with_capacity(35);

        command.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        command.extend_from_slice(&[0; 4]);
        command.extend_from_slice(&TPM_CC_EVICT_CONTROL.to_be_bytes());
        command.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        command.extend_from_slice(&handle.to_be_bytes());

        // authorizationSize, then TPMS_AUTH_COMMAND for TPM_RS_PW with an empty authValue
        command.extend_from_slice(&9u32.to_be_bytes());
        command.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        command.extend_from_slice(&0u16.to_be_bytes());
        command.push(0);
        command.extend_from_slice(&0u16.to_be_bytes());

        command.extend_from_slice(&handle.to_be_bytes());

        let command_size = u32::try_from(command.len()).expect("TPM command must fit in u32");
        command[2..6].copy_from_slice(&command_size.to_be_bytes());
        command
    }

    fn evict_persistent_handle(context: &TbsContext, handle: u32) {
        let command = evict_control_command(handle);
        let mut response = vec![0; RESPONSE_BUFFER_SIZE];
        let mut response_len = response.len() as u32;

        let status = unsafe {
            Tbsip_Submit_Command(
                context.0 as *const c_void,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                response.as_mut_ptr(),
                &mut response_len,
            )
        };
        assert_eq!(
            status, TBS_SUCCESS,
            "TBS rejected eviction of {handle:#010X}: {status:#010X}"
        );
        assert!(
            response_len >= 10,
            "TPM response for {handle:#010X} was too short"
        );

        let response_code = u32::from_be_bytes(response[6..10].try_into().unwrap());
        assert!(
            response_code == 0 || response_code == TPM_RC_OBJECT_HANDLE_NOT_FOUND,
            "failed to evict {handle:#010X}: TPM response {response_code:#010X}",
        );
    }

    #[test]
    #[ignore = "destructive: removes explicitly listed persistent TPM keys"]
    fn delete_created_persistent_keys() {
        let context = create_tbs_context();

        for handle in CREATED_PERSISTENT_HANDLES.into_iter().rev() {
            evict_persistent_handle(&context, handle);
        }
    }
}
