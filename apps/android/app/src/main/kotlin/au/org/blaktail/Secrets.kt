package au.org.blaktail

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets (WireGuard private key, node token, console credential) are stored
 * in SharedPreferences only as AES-256-GCM ciphertext under a non-exportable
 * Android Keystore key. Values written by older builds in plaintext are
 * re-sealed the first time they are read.
 */
object Secrets {
    private const val ALIAS = "au.org.blaktail.secrets"
    private const val PREFIX = "ks1:"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    fun seal(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val sealed = cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        return PREFIX + Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    /** Reads and decrypts `name`; null when absent or unreadable. */
    fun read(prefs: SharedPreferences, name: String): String? {
        val stored = prefs.getString(name, null) ?: return null
        if (!stored.startsWith(PREFIX)) {
            // Legacy plaintext from an older build: seal it in place.
            prefs.edit().putString(name, seal(stored)).apply()
            return stored
        }
        return runCatching {
            val raw = Base64.decode(stored.removePrefix(PREFIX), Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, raw, 0, IV_BYTES))
            String(cipher.doFinal(raw, IV_BYTES, raw.size - IV_BYTES), Charsets.UTF_8)
        }.getOrNull()
    }

    @Synchronized
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }
}
