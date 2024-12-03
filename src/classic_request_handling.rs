use advance_runner::run_advance;
use advance_runner::YieldManualReason;
use futures_channel::oneshot::Sender;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::collections::HashMap;
use std::io::Error;
use std::path::Path;
use std::sync::Condvar;
use std::sync::{Arc, Mutex};
pub(crate) fn add_request_to_database(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    requests: Arc<Mutex<HashMap<i64, Sender<i64>>>>,
    sender: Sender<i64>,
    machine_snapshot_path: &Path,
    payload: &Vec<u8>,
    no_console_putchar: &bool,
    priority: &i64,
) {
    let no_console_putchar: i64 = match no_console_putchar {
        true => 1,
        false => 0,
    };
    // Write down new request to the DB
    let id: i64  = sqlite_connection.query_row("INSERT INTO requests (machine_snapshot_path, payload, no_console_putchar, priority) VALUES (?, ?, ?, ?) RETURNING id;", params![machine_snapshot_path.to_str(), payload, no_console_putchar, priority], |row| row.get(0)
).unwrap();
    let mut requests = requests.lock().unwrap();
    requests.insert(id, sender);
}
pub(crate) fn check_previously_handled_results(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    machine_snapshot_path: &Path,
    payload: &Vec<u8>,
    no_console_putchar: &bool,
    priority: &i64,
    outputs_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    reports_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    finish_result: &mut Option<(u16, Vec<u8>)>,
    reason: &mut Option<advance_runner::YieldManualReason>,
) {
    let mut statement = sqlite_connection
    .prepare(
        "SELECT * FROM results WHERE machine_snapshot_path = ? AND payload = ? AND no_console_putchar = ? AND priority = ?;",
    )
    .unwrap();

    let mut rows = statement
        .query(params![
            machine_snapshot_path.to_str(),
            payload,
            no_console_putchar,
            priority
        ])
        .unwrap();
    if let Some(statement) = rows.next().unwrap() {
        println!("this request has been already handled");
        *outputs_vector = bincode::deserialize(&statement.get::<_, Vec<u8>>(1).unwrap()).ok();
        *reports_vector = bincode::deserialize(&statement.get::<_, Vec<u8>>(2).unwrap()).ok();
        *finish_result = bincode::deserialize(&statement.get::<_, Vec<u8>>(3).unwrap()).ok();
        *reason = match &statement.get::<_, i64>(4).unwrap() {
            1 => Some(YieldManualReason::Accepted),
            2 => Some(YieldManualReason::Rejected),
            4 => Some(YieldManualReason::Exception),
            _ => None,
        }
    }
}

pub(crate) fn query_result_from_database(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    id: &i64,
    outputs_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    reports_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    finish_result: &mut Option<(u16, Vec<u8>)>,
    reason: &mut Option<advance_runner::YieldManualReason>,
) {
    // Query the result from the DB
    let mut statement = sqlite_connection
        .prepare("SELECT * FROM results WHERE id = ?")
        .unwrap();

    let mut rows = statement.query([id]).unwrap();

    if let Some(statement) = rows.next().unwrap() {
        *outputs_vector = bincode::deserialize(&statement.get::<_, Vec<u8>>(1).unwrap()).ok();
        *reports_vector = bincode::deserialize(&statement.get::<_, Vec<u8>>(2).unwrap()).ok();
        *finish_result = bincode::deserialize(&statement.get::<_, Vec<u8>>(3).unwrap()).ok();
        *reason = match &statement.get::<_, i64>(4).unwrap() {
            1 => Some(YieldManualReason::Accepted),
            2 => Some(YieldManualReason::Rejected),
            4 => Some(YieldManualReason::Exception),
            _ => None,
        }
    }
}

pub(crate) fn query_request_with_the_highest_priority(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    new_record: Arc<(Mutex<bool>, Condvar)>,
) -> ClassicRequest {
    let mut statement = sqlite_connection
        .prepare(
            "WITH highest_priority_row AS (
                        SELECT *
                        FROM requests
                        ORDER BY priority DESC
                        LIMIT 1
                    )
                    DELETE FROM requests
                    WHERE id IN (SELECT id FROM highest_priority_row)
                    RETURNING *;
            ",
        )
        .unwrap();

    loop {
        let mut rows = statement.query([]).unwrap();
        let res = rows.next().unwrap();
        if let Some(statement) = res {
            return ClassicRequest {
                id: statement.get(0).unwrap(),
                machine_snapshot_path: statement.get(1).unwrap(),
                payload: statement.get(2).unwrap(),
                no_console_putchar: statement.get(3).unwrap(),
                priority: statement.get(4).unwrap(),
            };
        } else {
            println!("Waiting for new data to come in");
            let (lock, cvar) = &*new_record;
            let mut record = lock.lock().unwrap();
            while !*record {
                // Waits till new record in the DB
                record = cvar.wait(record).unwrap();
            }

            *record = false;
        }
    }
}

pub(crate) fn handle_database_request(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    classic_request: &ClassicRequest,
    requests: Arc<Mutex<HashMap<i64, Sender<i64>>>>,
) {
    let response = handle_classic(classic_request).unwrap();

    let reason = match response.1 {
        YieldManualReason::Accepted => 1,
        YieldManualReason::Rejected => 2,
        YieldManualReason::Exception => 4,
    };

    sqlite_connection.execute("INSERT INTO results (id, outputs_vector, reports_vector, finish_result, reason, machine_snapshot_path, payload, no_console_putchar, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", params![classic_request.id, bincode::serialize(&response.0.outputs_vector).unwrap(), bincode::serialize(&response.0.reports_vector).unwrap(), bincode::serialize(&response.0.finish_result).unwrap(), reason, classic_request.machine_snapshot_path, classic_request.payload, classic_request.no_console_putchar, classic_request.priority])
.unwrap();
    let mut requests: std::sync::MutexGuard<'_, HashMap<i64, Sender<i64>>> =
        requests.lock().unwrap();
    match requests.remove(&classic_request.id) {
        Some(sender) => {
            // Send a signal back to the service request handler, that the result was written into the DB
            let _ = sender.send(classic_request.id);
        }
        None => {}
    }
}

pub(crate) fn handle_classic(
    classic_request: &ClassicRequest,
) -> Result<(RunAdvanceResponses, YieldManualReason), Box<dyn std::error::Error>> {
    let no_console_putchar = match classic_request.no_console_putchar {
        0 => false,
        1 => true,
        _ => panic!(
            "no_console_putchar should be 0 or 1: {}",
            classic_request.no_console_putchar
        ),
    };
    let mut outputs_vector: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut reports_vector: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut finish_result: (u16, Vec<u8>) = (0, vec![0]);
    let output_callback = |reason: u16, payload: &[u8]| {
        let mut result: Result<(u16, Vec<u8>), Error> = Ok((reason, payload.to_vec()));
        outputs_vector.push(result.as_mut().unwrap().clone());
        return result;
    };

    let report_callback = |reason: u16, payload: &[u8]| {
        let mut result: Result<(u16, Vec<u8>), Error> = Ok((reason, payload.to_vec()));
        reports_vector.push(result.as_mut().unwrap().clone());
        return result;
    };
    let finish_callback = |reason: u16, payload: &[u8]| {
        let mut result: Result<(u16, Vec<u8>), Error> = Ok((reason, payload.to_vec()));
        finish_result = result.as_mut().unwrap().clone();
        return result;
    };
    let reason = run_advance(
        classic_request.machine_snapshot_path.clone(),
        None,
        classic_request.payload.clone(),
        HashMap::new(),
        &mut Box::new(report_callback),
        &mut Box::new(output_callback),
        &mut Box::new(finish_callback),
        HashMap::new(),
        no_console_putchar,
    )?;

    Ok((
        RunAdvanceResponses {
            outputs_vector,
            reports_vector,
            finish_result,
        },
        reason,
    ))
}

#[derive(Debug)]
pub(crate) struct RunAdvanceResponses {
    pub outputs_vector: Vec<(u16, Vec<u8>)>,
    pub reports_vector: Vec<(u16, Vec<u8>)>,
    pub finish_result: (u16, Vec<u8>),
}

pub(crate) struct ClassicRequest {
    pub id: i64,
    pub machine_snapshot_path: String,
    pub payload: Vec<u8>,
    pub no_console_putchar: i64,
    pub priority: i64,
}
