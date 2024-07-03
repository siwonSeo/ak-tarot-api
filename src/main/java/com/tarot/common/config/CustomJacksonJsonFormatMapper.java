package com.tarot.common.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hibernate.type.descriptor.WrapperOptions;
import org.hibernate.type.descriptor.java.JavaType;
import org.hibernate.type.format.FormatMapper;

public class CustomJacksonJsonFormatMapper implements FormatMapper {
    private final ObjectMapper objectMapper;

    public CustomJacksonJsonFormatMapper() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public <T> T fromString(CharSequence charSequence, JavaType<T> javaType, WrapperOptions wrapperOptions) {
        try {
            return objectMapper.readValue(charSequence.toString(), objectMapper.constructType(javaType.getJavaType()));
        } catch (Exception e) {
            throw new RuntimeException("Error deserializing JSON", e);
        }
    }

    @Override
    public <T> String toString(T value, JavaType<T> javaType, WrapperOptions wrapperOptions) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new RuntimeException("Error serializing to JSON", e);
        }
    }
}
