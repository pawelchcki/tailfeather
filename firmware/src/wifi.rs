//! Keeping the station associated with the access point.

use embassy_time::{Duration, Timer};
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config, WifiController};
use log::{info, warn};

/// How long to wait before retrying an association. Long enough that a router
/// rebooting is not hammered, short enough that the gateway comes back on its
/// own without anyone power-cycling it.
const RETRY_DELAY: Duration = Duration::from_secs(5);

#[embassy_executor::task]
pub async fn connection(mut controller: WifiController<'static>) -> ! {
    let config = Config::Station(
        StationConfig::default()
            .with_ssid(crate::WIFI_SSID)
            .with_password(crate::WIFI_PASSWORD.into()),
    );
    // Setting the configuration also starts the radio; there is no separate
    // start call in esp-radio 0.18.
    controller
        .set_config(&config)
        .expect("the station configuration is valid");

    loop {
        match controller.connect_async().await {
            Ok(info) => {
                info!("associated with {}", info.ssid.as_str());
                // The link can drop for reasons the DHCP client never sees, so
                // the disconnect event is what drives reassociation.
                let reason = controller.wait_for_disconnect_async().await;
                warn!("disconnected: {reason:?}");
            }
            Err(e) => warn!("association failed: {e:?}"),
        }
        Timer::after(RETRY_DELAY).await;
    }
}
