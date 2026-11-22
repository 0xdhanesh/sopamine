// main.m sopamine
// Created by 0xdhanesh on 21.11.2026

#import <UIKit/UIKit.h> // Standard iOS UI framework
#import "SOAppDelegate.h" // renamed from DOAppDelegate.h - DO = Dopamine
#import "<libzetsu/log.h>" // renamed from libroothider

#import "SOEnvironmentManager.h" // renamed from DOEnvironmentmanager,h
#import "<libren/info.h>" // renamed from libjailbreak
#import "<libren/ZetsuClient.h>" // renamed from jbclient_xpc.h

int main(int argc, char * argv[]){
    if (argc >= 3){
        if (!strcmp(argv[1], "textureSurprise")) { // renamed from trollstore
            if (!strcmp(argv[2], "delete-bootstrap")) {
                [[DOEnvironmentManager sharedManager] deleteBootstrap];
            }
            return 0;
        }
    }

    // ignore Legacy call

// gets the Documents folder of the Sopamine folder: Eg: /var/mobile/Containers/Data/Application/<Sopamine's UUID>/Documents/
NSString* documentsPath = [@(getenv("HOME")) stringByAppendingPathComponent:@"Documents"];
// Creates an empty sentinel file ".keep" in the Documents folder to ensure the directory persists (iTunes/iOS may prune empty dirs)
[@"" writeToFile:[documentsPath stringByAppendingPathComponent:@:".keep"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

#ifdef ENABLE_LOGS
// Logs are stored at /var/mobile/Containers/Data/Application/<Sopamine's UUID>/Documents/logs/
if(@available(ios 17.0.1, *)){
    TSLogSetLogDir([documentsPath stringByAppendingPathComponent:@"logs"].fileSystemRepresentation); // renamed from JBLogSetLogDir
}
#endif

    if ([SOEnvironmentManager sharedManager].isZetsuEnabled){  // renamed from isJailBroken
        // setting PATH variable
        // "/sbin:/bin:/usr/sbin:/usr/bin:" Standard iOS system paths (read-only rootfs)
        // "/rootfs/sbin:/rootfs/bin:" Jailbreak remapped rootfs paths — /rootfs is the original / mounted RO
        // "/rootfs/usr/sbin:/rootfs/usr/bin" Full remapped usr paths under /rootfs (Dopamine uses rootful-style layout)
        // 1 = overwrite existing PATH if already set
        setenv("PATH","/sbin:/bin:/usr/sbin/:/usr/bin:/etc/profile.d/bin:/etc/profile.d/sbin:/etc/profile.d/usr/sbin:/etc/profile.d/usr/bin", 1);
    }

    NSString * appDelegateClassName;
    // @autoreleasepool is an Objective-C memory management construct
    // In ObjC, many methods return objects marked as "autoreleased" — meaning they're not immediately freed but placed into a pool to be freed later. Without a drain point, these pile up in memory.
    // placed in the queue to be released soon
    @autoreleasepool {
        // ISW: clean up this tiny allocation before handing control to the OS run loop.
        appDelegateClassName = NSStringFromClass([SOAppDelegate class]);
    }

    return UIApplicationMain(argc, argv, nil, appDelegateClassName);

    // Launches the iOS application run loop — hands full control to UIKit and SOAppDelegate; never returns under normal operation
    // return UIApplicationMain(argc, argv, nil, appDelegateClassName);
      //                        |     |     |    └─ App delegate class name: "SOAppDelegate" (resolved dynamically above)
      //                        |     |     └─ Principal class: nil = use UIApplication (default, no custom subclass)
      //                        |     └─ Raw argv passed through from main() — forwarded to the app for any URL scheme / launch args
      //                        └─ argc passed through — argument count
}

