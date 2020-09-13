package com.example.Customers.CryptoConverter;

import org.springframework.stereotype.Component;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.AttributeConverter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Base64;

@Component
public class Encryptor implements AttributeConverter<String, String> {

    private static final String ALGORITHM = "AES";
    private static final String TEMP_KEY = "CRUDApplicationAdksAdks1";

    private final Key key;
    private final Cipher cipher;

    public Encryptor() throws Exception {
        key = new SecretKeySpec(TEMP_KEY.getBytes(), ALGORITHM);
        cipher = Cipher.getInstance(ALGORITHM);
    }

    @Override
    public String convertToDatabaseColumn(String unencrypted_data) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            Base64.Encoder encoder=Base64.getEncoder();
            return encoder.encodeToString(cipher.doFinal(unencrypted_data.getBytes()));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String convertToEntityAttribute(String encrypted_data) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            Base64.Decoder decoder=Base64.getDecoder();
            return new String(cipher.doFinal(decoder.decode(encrypted_data)));
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
    }
}