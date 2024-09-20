# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

-keep class com.krxkli.crackmm.* {
    native <methods>;
}

-keep class com.krxkli.crackmm.core.PktProcessor {
    helpProtectSocket(int);
}

# 输出mapping.txt文件
-printmapping ./build/outputs/mapping/release/mapping.txt

# 输出seeds.txt文件
-printseeds ./build/outputs/mapping/release/seeds.txt

# 输出usage.txt文件
-printusage ./build/outputs/mapping/release/usage.txt

