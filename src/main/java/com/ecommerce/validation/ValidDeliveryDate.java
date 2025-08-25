package com.ecommerce.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = DeliveryDateValidator.class)
@Documented
public @interface ValidDeliveryDate {
    String message() default "Delivery date must be today or in the future and not on Sunday";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}