package com.ecommerce.validation;

public enum DeliveryTime {
    TIME_10AM("10AM"),
    TIME_11AM("11AM"),
    TIME_12PM("12PM");

    private final String displayTime;

    DeliveryTime(String displayTime) {
        this.displayTime = displayTime;
    }

    public String getDisplayTime() {
        return displayTime;
    }
}