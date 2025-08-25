package com.ecommerce.validation;

public enum ProductName {
    SMARTPHONE_X100("Smartphone X100"),
    WIRELESS_HEADPHONES("Wireless Headphones"),
    LAPTOP_PRO("Laptop Pro 15"),
    TABLET_AIR("Tablet Air 11"),
    SMART_WATCH("Smart Watch Series 5"),
    BLUETOOTH_SPEAKER("Bluetooth Speaker"),
    GAMING_CONSOLE("Gaming Console X"),
    DIGITAL_CAMERA("Digital Camera 4K"),
    POWER_BANK("Power Bank 20000mAh"),
    WIRELESS_CHARGER("Wireless Charger Pad");

    private final String displayName;

    ProductName(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}