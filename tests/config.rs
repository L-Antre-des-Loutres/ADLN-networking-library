use std::time::Duration;

use adln_networking::{ConfigError, GameId, ServerConfig};

fn config() -> ServerConfig {
    ServerConfig::new("127.0.0.1:0".parse().unwrap(), GameId(19), vec![2, 3])
}

#[test]
fn capacities_protect_the_process_without_imposing_game_population_rules() {
    let mut config = config();
    config.max_connections = 200;
    assert!(config.validate().is_ok());
    config.max_connections = 0;
    assert_eq!(config.validate(), Err(ConfigError::Limits));
    config.max_connections = 8193;
    assert_eq!(config.validate(), Err(ConfigError::Limits));
}

#[test]
fn rejects_invalid_application_versions_and_unusable_transport_budgets() {
    for versions in [vec![], vec![0], vec![1, 1]] {
        let mut config = config();
        config.application_versions = versions;
        assert_eq!(config.validate(), Err(ConfigError::Application));
    }
    let mut config = config();
    config.idle_timeout = Duration::from_millis(20);
    assert_eq!(config.validate(), Err(ConfigError::Timers));
    config.idle_timeout = Duration::from_secs(15);
    config.per_connection.packets_per_second = 0;
    assert_eq!(config.validate(), Err(ConfigError::Limits));
    config.per_connection.packets_per_second = 100;
    config.max_payload = 1025;
    assert_eq!(config.validate(), Err(ConfigError::Limits));
    config.max_payload = 8;
    assert!(config.validate().is_ok());
    config.per_connection.bytes_per_second = 1;
    assert_eq!(config.validate(), Err(ConfigError::Limits));
}
