#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::task_store::TaskStore;

fuzz_target!(|data: (u8, u8, &str)| {
    let (max_raw, ttl_raw, id_data) = data;
    let max = (max_raw % 10) as usize + 1;
    let ttl_ms = u64::from(ttl_raw) * 100 + 100;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let store = TaskStore::new(max, ttl_ms, 500);

        // Create a task
        if let Some((id, _token)) = store.create_task().await {
            let _ = store.get_task(&id).await;
            let _ = store.get_result(&id).await;

            // Action based on fuzz data
            match id_data.len() % 3 {
                0 => {
                    let _ = store
                        .complete_task(&id, serde_json::json!({"ok": true}))
                        .await;
                }
                1 => {
                    let _ = store
                        .fail_task(&id, id_data, serde_json::json!({"err": true}))
                        .await;
                }
                _ => {
                    let _ = store.cancel_task(&id).await;
                }
            }

            let _ = store.get_task(&id).await;
            let _ = store.get_result(&id).await;
        }

        // No cursor fuzzing left: `list_tasks` went with `tasks/list`,
        // and with it the only cursor this store ever parsed.

        // Try operations on non-existent task
        let _ = store.cancel_task(id_data).await;
        let _ = store.get_task(id_data).await;

        store.cleanup().await;
    });
});
