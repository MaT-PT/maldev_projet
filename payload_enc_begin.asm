PUBLIC aes_key
PUBLIC aes_iv
PUBLIC __payload_enc_start

injected SEGMENT READ EXECUTE

; Will be replaced by the obfuscated AES key
aes_key LABEL PTR BYTE
    BYTE 16 DUP(?)

; Will be replaced by the obfuscated AES IV
aes_iv LABEL PTR BYTE
    BYTE 16 DUP(?)

__payload_enc_start:

injected ENDS

END
