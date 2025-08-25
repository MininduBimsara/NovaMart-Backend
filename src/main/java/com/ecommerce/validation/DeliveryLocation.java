package com.ecommerce.validation;

public enum DeliveryLocation {
    COLOMBO("Colombo"),
    GAMPAHA("Gampaha"),
    KALUTARA("Kalutara"),
    KANDY("Kandy"),
    MATALE("Matale"),
    NUWARA_ELIYA("Nuwara Eliya"),
    GALLE("Galle"),
    MATARA("Matara"),
    HAMBANTOTA("Hambantota"),
    JAFFNA("Jaffna"),
    KILINOCHCHI("Kilinochchi"),
    MANNAR("Mannar"),
    VAVUNIYA("Vavuniya"),
    MULLAITIVU("Mullaitivu"),
    BATTICALOA("Batticaloa"),
    AMPARA("Ampara"),
    TRINCOMALEE("Trincomalee"),
    KURUNEGALA("Kurunegala"),
    PUTTALAM("Puttalam"),
    ANURADHAPURA("Anuradhapura"),
    POLONNARUWA("Polonnaruwa"),
    BADULLA("Badulla"),
    MONERAGALA("Moneragala"),
    RATNAPURA("Ratnapura"),
    KEGALLE("Kegalle");

    private final String displayName;

    DeliveryLocation(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}