package org.acme.kms;

import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.Base64;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

@Path("/sync")
@Produces(MediaType.TEXT_PLAIN)
@Consumes(MediaType.TEXT_PLAIN)
public class QuarkusKmsSyncResource {

    @Inject
    KmsClient kms;

    @ConfigProperty(name = "key.arn")
    String keyArn;

    @POST
    @Path("/encrypt")
    public String encrypt(String data) {
        SdkBytes encryptedBytes = kms.encrypt(req -> req.keyId(keyArn).encryptionAlgorithm("RSAES_OAEP_SHA_256").plaintext(SdkBytes.fromUtf8String(data))).ciphertextBlob();


        return Base64.getEncoder().encodeToString(encryptedBytes.asByteArray());
    }

    @POST
    @Path("/decrypt")
    public String decrypt(String data) {
        SdkBytes encryptedData = SdkBytes.fromByteArray(Base64.getDecoder().decode(data.getBytes()));
        DecryptResponse decrypted = kms.decrypt(req -> req.keyId(keyArn).encryptionAlgorithm("RSAES_OAEP_SHA_256").ciphertextBlob(encryptedData));

        return decrypted.plaintext().asUtf8String();
    }
}
