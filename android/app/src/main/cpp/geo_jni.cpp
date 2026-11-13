#include <jni.h>

#include <string>
#include <unordered_map>

#include "GeoDbBridge.h"

namespace {

jobject new_lookup_map(JNIEnv *env) {
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID init = env->GetMethodID(mapClass, "<init>", "()V");
    return env->NewObject(mapClass, init);
}

void put(JNIEnv *env, jobject map, const char *key, const std::string &value) {
    jclass mapClass = env->FindClass("java/util/HashMap");
    jmethodID put = env->GetMethodID(mapClass, "put",
                                    "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    env->CallObjectMethod(map, put, env->NewStringUTF(key), env->NewStringUTF(value.c_str()));
}

}  // namespace

extern "C" {

JNIEXPORT jlong JNICALL Java_com_redsalmons_linkatlas_geo_NativeGeoDb_open(
        JNIEnv *env, jobject, jstring path) {
    const char *text = env->GetStringUTFChars(path, nullptr);
    void *database = linkatlasGeoOpen(text);
    env->ReleaseStringUTFChars(path, text);
    return reinterpret_cast<jlong>(database);
}

JNIEXPORT void JNICALL Java_com_redsalmons_linkatlas_geo_NativeGeoDb_close(
        JNIEnv *, jobject, jlong handle) {
    linkatlasGeoClose(reinterpret_cast<void *>(handle));
}

JNIEXPORT jobject JNICALL Java_com_redsalmons_linkatlas_geo_NativeGeoDb_lookup(
        JNIEnv *env, jobject, jlong handle, jstring address, jstring locale) {
    const char *ip = env->GetStringUTFChars(address, nullptr);
    const char *language = env->GetStringUTFChars(locale, nullptr);
    LinkAtlasGeoLookup result;
    bool ok = linkatlasGeoLookup(reinterpret_cast<void *>(handle), ip, language, &result);
    env->ReleaseStringUTFChars(address, ip);
    env->ReleaseStringUTFChars(locale, language);

    jobject map = new_lookup_map(env);
    if (!ok) return map;
    put(env, map, "status", std::to_string(result.status));
    put(env, map, "countryCode", result.countryCode);
    put(env, map, "countryName", result.countryName);
    put(env, map, "region", result.region);
    put(env, map, "city", result.city);
    if (result.hasLatitude) put(env, map, "latitude", std::to_string(result.latitude));
    if (result.hasLongitude) put(env, map, "longitude", std::to_string(result.longitude));
    if (result.asn != 0) put(env, map, "asn", std::to_string(result.asn));
    put(env, map, "org", result.organization);
    return map;
}

}  // extern "C"
