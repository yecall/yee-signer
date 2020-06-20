//
//  ViewController.m
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "ViewController.h"
#import "libyee_signer.h"
#import "NSData+HexString.h"
#import "KeyPair.h"
#import "Verifier.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    [self testFromMiniSecretKey];
    
    [self testFromMiniSecretKeyFail];
    
    [self testFromSecretKey];
    
    [self testVerify];
    
    [self testVerifyFail];
    
}

- (void)testFromMiniSecretKey {
    
    NSError* error = nil;
    
    NSData* miniSecretKey = [NSData fromHex:@"579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"];
    
    KeyPair* keyPair = [KeyPair fromMiniSecretKey:miniSecretKey error: &error];
        
    NSData *publicKey = [keyPair publicKey:&error];
        
    NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");
    
    NSData *secretKey = [keyPair secretKey:&error];
            
    NSAssert([[secretKey toHex] isEqualToString:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    
    [keyPair free:&error];
    
}

- (void)testFromMiniSecretKeyFail {
    
    NSError* error = nil;
    
    NSData* miniSecretKey = [NSData fromHex:@"579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43"];
    
    KeyPair* keyPair = [KeyPair fromMiniSecretKey:miniSecretKey error: &error];
        
    NSAssert([[error.userInfo valueForKey:@"message"] isEqualToString:@"invalid mini secret key"], @"");
    
    [keyPair free:&error];
}

- (void)testFromSecretKey {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
        
    NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");
    
    NSData *secretKey2 = [keyPair secretKey:&error];
            
    NSAssert([[secretKey2 toHex] isEqualToString:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    
    [keyPair free:&error];
}

- (void)testVerify {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
    
    Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
        
    NSData *message = [NSData fromHex:@"010203"];
    
    NSData *signature = [keyPair sign:message error:&error];
    
    BOOL ok = [verifier verify:signature message:message error:&error];
    
    NSAssert(ok, @"");
    
    [keyPair free:&error];
    
    [verifier free:&error];
    
}

- (void)testVerifyFail {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
    
    Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
        
    NSData *message = [NSData fromHex:@"010203"];
    
    NSData *signature = [NSData fromHex:@"010203"];
    
    BOOL ok = [verifier verify:signature message:message error:&error];
    
    NSAssert(!ok, @"");
    
    [keyPair free:&error];
    
    [verifier free:&error];
    
}


@end
