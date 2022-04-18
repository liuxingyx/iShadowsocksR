//
//  ViewController.m
//  mbedtls-for-ios
//
//  Created by ssrlive on 2/12/18.
//  Copyright © 2018 ssrLive. All rights reserved.
//

#import "ViewController.h"
#import <mbedtls/mbedtls.h>

@interface ViewController ()
@property (strong, nonatomic) IBOutlet UITextField *textField;
@property (strong, nonatomic) IBOutlet UILabel *md5TextField;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction) calculateMD5:(UIButton *)sender {
    /** Calculate MD5*/
    const char *inStr = [_textField.text UTF8String];
    unsigned char result[16];
    
    mbedtls_md5_ret( (unsigned char *) inStr, strlen(inStr), result );
    
    NSMutableString *outStrg = [[NSMutableString alloc] init];
    for (int i=0; i<16; ++i) {
        [outStrg appendFormat:@"%02x", result[i]];
    }
    _md5TextField.text = outStrg;
    
    //Hide Keyboard after calculation
    [_textField resignFirstResponder];
}

- (IBAction) showInfo:(id)sender {
    char ver[256] = { 0 };
    mbedtls_version_get_string_full(ver);
    NSString *msg = @"%s\n\nLicense: See mbedtls/LICENSE\n\nCopyright 2018 by ssrLive\n http://github.com/ssrlive";
    UIAlertView *alert =
    [[UIAlertView alloc] initWithTitle:@"mbedTLS demo for iOS"
                               message:[NSString stringWithFormat:msg, ver]
                              delegate:nil
                     cancelButtonTitle:@"Close"
                     otherButtonTitles:nil];
    [alert show];
}

@end
