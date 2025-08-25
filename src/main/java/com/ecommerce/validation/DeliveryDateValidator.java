package com.ecommerce.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.time.DayOfWeek;
import java.time.LocalDate;

public class DeliveryDateValidator implements ConstraintValidator<ValidDeliveryDate, LocalDate> {

    @Override
    public void initialize(ValidDeliveryDate constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(LocalDate date, ConstraintValidatorContext context) {
        if (date == null) {
            return false;
        }

        LocalDate today = LocalDate.now();

        // Date must be today or in the future
        if (date.isBefore(today)) {
            return false;
        }

        // Date must not be Sunday
        return date.getDayOfWeek() != DayOfWeek.SUNDAY;
    }
}