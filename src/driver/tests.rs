use super::adapter::*;

#[test]
fn test_detect_physical_adapter() {
    let phy = detect_physical_adapter();
    println!("[TEST] Detected Physical Adapter: {:?}", phy);
    assert!(!is_virtual_adapter_name(&phy.adapter_name));
    assert!(phy.lan_ip != [0, 0, 0, 0]);
    assert_ne!(phy.gateway, "0.0.0.0");
    assert_ne!(phy.gateway, "On-link");
}
