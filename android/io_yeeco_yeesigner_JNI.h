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
 * Signature: (J[B[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_sign
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray);

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
 * Signature: (J[B[B[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_verify
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     io_yeeco_yeesigner_JNI
 * Method:    verifierFree
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_io_yeeco_yeesigner_JNI_verifierFree
  (JNIEnv *, jclass, jlong, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
