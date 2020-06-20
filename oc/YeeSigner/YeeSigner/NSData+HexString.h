//
//  NSData+HexString.h
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NSData_HexString)

- (NSString *)toHex;

+ (id)fromHex: (NSString *)hex;

@end
