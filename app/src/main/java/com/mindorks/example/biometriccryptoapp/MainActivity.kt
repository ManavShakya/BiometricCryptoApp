package com.mindorks.example.biometriccryptoapp

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {

    private lateinit var mainLayout: View
    private lateinit var editText: EditText
    private lateinit var cryptButton : Button
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private var isEncrypt: Boolean = false
    private var isAuthorised: Boolean = false
    private lateinit var ciphertext : ByteArray
    private lateinit var initializationVector: ByteArray
    private val encryptionBlockMode : String = KeyProperties.BLOCK_MODE_GCM
    private val encryptionPadding : String = KeyProperties.ENCRYPTION_PADDING_NONE
    private val encryptionAlgorithm : String = KeyProperties.KEY_ALGORITHM_AES
    private val tag = "mainActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        mainLayout = findViewById(R.id.main_layout)
        mainLayout.visibility = View.GONE
        val biometricManager: BiometricManager = BiometricManager.from(this)
        checkHardwareAndAuthenticate(biometricManager)
        editText = findViewById(R.id.editText)
        cryptButton = findViewById(R.id.crypt_button)
        cryptButton.text = getString(R.string.button_encrypt)
        cryptButton.setOnClickListener( object: View.OnClickListener{
            override fun onClick(v: View?) {
                performCryptography() // this functions performs both encryption/decryption
            }
        })
    }

    /**
     * function to check if the user’s device supports biometric features before you perform any authentication.
     */
    private fun checkHardwareAndAuthenticate(biometricManager: BiometricManager) {
        when (biometricManager.canAuthenticate()) {

            BiometricManager.BIOMETRIC_SUCCESS -> authenticateUser()
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Toast
                    .makeText(this, "No Biometric Hardware..", Toast.LENGTH_LONG).show()
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Toast
                    .makeText(this, "Biometric features are currently unavailable", Toast.LENGTH_LONG).show()
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Toast
                    .makeText(this, "Please setup fingerprint and try again", Toast.LENGTH_LONG).show()
        }
    }

    private fun authenticateUser(){

        // promptInfo and biometricPrompt are initialised here and will be used in both use cases
        biometricPrompt = createBiometricPrompt()
        promptInfo = createPromptInfo()

        biometricPrompt.authenticate(promptInfo)

    }

    private fun createPromptInfo(): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authentication Required")
                .setSubtitle("Log in using Biometric")
                .setDescription("Touch your fingerprint sensor to authenticate")
                .setNegativeButtonText("Cancel")
                //.setDeviceCredentialAllowed(true)
                //.setConfirmationRequired(true)
                .build()
    }

    private fun createBiometricPrompt(): BiometricPrompt {

        val executor : Executor = ContextCompat.getMainExecutor(this)
        return BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d("MainActivity", "Authentication was successful")
                if(isAuthorised) // this flag is used to differentiate the use case of authentication
                    convertInput(result.cryptoObject)
                else{
                    mainLayout.visibility = View.VISIBLE
                    isAuthorised = true
                }
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.d(tag, "$errorCode :: $errString")
                if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                    biometricPrompt.cancelAuthentication()
                    editText.setText(R.string.sampletext)
                    cryptButton.text = getString(R.string.button_encrypt)
                    isEncrypt = false
                }
            }
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.d(tag, "Authentication failure")
            }
        })
    }

    private fun performCryptography() {

        // Initializing a cipher template with chosen transformation
        val cipher : Cipher = Cipher.getInstance("$encryptionAlgorithm/$encryptionBlockMode/$encryptionPadding")
        // Fetches/creates an instance of SecretKey using [Cipher.ENCRYPT_MODE]/[Cipher.DECRYPT_MODE] and
        // then initializes the Cipher with that key for encryption/decryption.
        val secretKey : SecretKey = getSecretKey()
        isEncrypt = if(!isEncrypt){
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            true
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey,GCMParameterSpec(128,initializationVector))
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            false
        }
    }

    private fun getSecretKey(): SecretKey {

        // fetch the key if it is already present
        val keyName = "myKey"
        val androidKeystore = "AndroidKeyStore"
        val keyStore: KeyStore = KeyStore.getInstance(androidKeystore)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        // if Secret key is not present, then it is created and returned
        val keyGenParameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(encryptionBlockMode)
                .setEncryptionPaddings(encryptionPadding)
                .setUserAuthenticationRequired(true)
                .build()
        val keyGenerator: KeyGenerator = KeyGenerator.getInstance(encryptionAlgorithm, androidKeystore)
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    private fun convertInput(cryptoObject: BiometricPrompt.CryptoObject?) {
        val cipher = cryptoObject?.cipher
        val input: String = if(isEncrypt) {
            val plaintext: String = editText.text.toString()
            ciphertext = cipher!!.doFinal(plaintext.toByteArray())
            initializationVector = cipher.iv
            cryptButton.text = getString(R.string.button_decrypt)
            String(ciphertext)

        } else {
            val plaintext : ByteArray = cipher!!.doFinal(ciphertext)
            cryptButton.text = getString(R.string.button_encrypt)
            String(plaintext)
        }
        editText.setText(input)
    }

}
