package com.rocktech.jwt.security.jwt.advice;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.StackManipulation;

import java.util.Date;

@AllArgsConstructor
@Getter
@Setter
public class ErrorMessage{
    private int statusCode;
    private Date timestamp;
    private String message;
    private String description;
}
