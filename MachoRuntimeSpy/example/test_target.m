#import <Foundation/Foundation.h>

@interface MyObject : NSObject {
    int t;
}
- (void) printt: (int) t;
@end

@implementation MyObject

- (void) printt:(int)t {
    NSLog(@"Hello, World!");
}
@end

int main(int argc, const char * argv[]) {
    MyObject * ob = [[MyObject alloc] init];
    [ob printt:0];
    NSLog(@"Hello, World!");
    while(1)
        sleep(3);
    return 0;
}

