use std::sync::atomic::{AtomicPtr, Ordering};

use chrono::prelude::*;

static mut NTP_OFFSET: AtomicPtr<chrono::Duration> =
    AtomicPtr::new(std::ptr::null_mut());
static mut LAST_CHECK: AtomicPtr<DateTime<Utc>> =
    AtomicPtr::new(std::ptr::null_mut());

pub fn rfc3339() -> String {
    return now().to_rfc3339();
}

pub fn unix() -> i64 {
    return now().timestamp();
}

fn now() -> DateTime<Utc> {
    let ts = Utc::now();

    unsafe {
        let last_check = LAST_CHECK.load(Ordering::SeqCst);

        if last_check == std::ptr::null_mut() || (*last_check).time() < ts.time()  {
            if update_last_checked(last_check, ts) {
                update_ntp_offset();
            }
        }
    }

    let offset = ntp_offset();

    return ts + offset;
}

fn update_ntp_offset() {
    let stime = chrono::Utc::now();

    match ntp::request("time.google.com:123") {
        Ok(response) => {
            // calculate the ntp offset
            let dtime = chrono::Utc::now() - stime;
            let rtime = chrono::Duration::seconds(response.recv_time.sec as i64)
                + chrono::Duration::nanoseconds(response.recv_time.frac as i64);
            let otime = chrono::Duration::seconds(response.orig_time.sec as i64)
                + chrono::Duration::nanoseconds(response.orig_time.frac as i64);

            let a = rtime - otime;

            let offset = (a + dtime) / 2;

            unsafe {
                NTP_OFFSET.store(Box::into_raw(Box::new(offset)), Ordering::SeqCst);
            }
        }
        Err(err) => {
            println!("ntp lookup failed with: {}", err);
        }
    };
}

fn ntp_offset() -> chrono::Duration {
    unsafe {
        loop {
            let offset = NTP_OFFSET.load(Ordering::SeqCst);
            if offset != std::ptr::null_mut() {
                return *offset;
            }

            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

fn update_last_checked(
    checked: *mut DateTime<Utc>,
    current_timestamp: DateTime<Utc>,
) -> bool {
    unsafe {
        return match LAST_CHECK.compare_exchange(
            checked,
            Box::into_raw(Box::new(current_timestamp)),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => true,
            Err(_) => false,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339() {
        println!("utc: {} - rfc: {}", chrono::Utc::now(), rfc3339());
    }
}
