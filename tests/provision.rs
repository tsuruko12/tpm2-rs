mod log;

use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

use log::init_tracing;
use rusqlite::Connection;
use tempfile::TempDir;
use tpm_tool::Context;

const STORE_PATH_ENV: &str = "TPM_STORE_PATH";

struct TestStore {
    _temp_dir: TempDir,
    previous_path: Option<OsString>,
}

impl TestStore {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create isolated TPM store directory");

        let previous_path = env::var_os(STORE_PATH_ENV);
        // The test has a single test case, so no other test in this process can observe this
        // process-wide environment change
        unsafe { env::set_var(STORE_PATH_ENV, temp_dir.path()) };

        Self {
            _temp_dir: temp_dir,
            previous_path,
        }
    }

    fn database_path(&self) -> PathBuf {
        self._temp_dir.path().join("store.db")
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        match &self.previous_path {
            Some(path) => unsafe { env::set_var(STORE_PATH_ENV, path) },
            None => unsafe { env::remove_var(STORE_PATH_ENV) },
        }
    }
}

fn print_internal_persistent_objects(database_path: &Path) {
    let connection = Connection::open(database_path).expect("failed to open TPM store database");
    let mut statement = connection
        .prepare(
            "\
            SELECT kind, printf('0x%08X', handle), hex(object_name)
            FROM internal_persistent_objects
            ORDER BY kind
            ",
        )
        .expect("failed to query provisioned internal objects");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("failed to read provisioned internal objects");

    println!("internal_persistent_objects:");
    for row in rows {
        let (kind, handle, object_name) = row.expect("failed to decode internal object metadata");
        println!("  kind={kind}, handle={handle}, object_name={object_name}");
    }
}

#[cfg(target_os = "linux")]
fn connect() -> Context {
    Context::connect_from_env().expect("failed to connect to swtpm")
}

#[cfg(target_os = "windows")]
fn connect() -> Context {
    Context::connect().expect("failed to connect to the TPM")
}

#[test]
fn provision_creates_internal_keys() {
    init_tracing();
    let store = TestStore::new();
    let mut ctx = connect();

    ctx.provision().expect("failed to provision the TPM");
    drop(ctx);

    print_internal_persistent_objects(&store.database_path());
}
