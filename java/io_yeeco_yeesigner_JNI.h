/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class io_yeeco_yeesigner_JNI */

#ifndef _Included_io_yeeco_yeesigner_JNI
#define _Included_io_yeeco_yeesigner_JNI
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    keyPairFromMiniSecretKey
 * Signature: ([B[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_keyPairFromMiniSecretKey
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    keyPairFromSecretKey
 * Signature: ([B[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_keyPairFromSecretKey
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    publicKey
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_publicKey
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    secretKey
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_secretKey
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    sign
 * Signature: (J[B[B[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_sign
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    keyPairFree
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_keyPairFree
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    verifierFromPublicKey
 * Signature: ([B[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_verifierFromPublicKey
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    verify
 * Signature: (J[B[B[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_verify
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    verifierFree
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_verifierFree
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    buildCallBalanceTransfer
 * Signature: ([BJ[B[B[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_buildCallBalanceTransfer
  (JNIEnv *, jclass, jbyteArray, jlong, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    callFree
 * Signature: (JII[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_callFree
  (JNIEnv *, jclass, jlong, jint, jint, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    buildTx
 * Signature: ([BJJJ[BJII[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_buildTx
  (JNIEnv *, jclass, jbyteArray, jlong, jlong, jlong, jbyteArray, jlong, jint, jint, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    txFree
 * Signature: (JII[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_txFree
  (JNIEnv *, jclass, jlong, jint, jint, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    txLength
 * Signature: (JII[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_txLength
  (JNIEnv *, jclass, jlong, jint, jint, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    txEncode
 * Signature: (JII[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_txEncode
  (JNIEnv *, jclass, jlong, jint, jint, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    txDecode
 * Signature: ([B[B[B[B)J
 */
JNIEXPORT jlong JNICALL Java_io_yeeco_yeesigner_JNI_txDecode
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    verifyTx
 * Signature: (JII[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_verifyTx
  (JNIEnv *, jclass, jlong, jint, jint, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
