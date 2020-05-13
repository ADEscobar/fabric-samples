/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Wallets, HsmX509Provider } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const fs = require('fs');
const path = require('path');
const utils = require('fabric-common/lib/Utils');
async function main() {
    try {
        // load the network configuration
        const ccpPath = path.resolve(__dirname, '..', '..', 'first-network', 'connection-org1.json');
        const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));
        
        utils.setConfigSetting('crypto-hsm',true);
        utils.setConfigSetting('crypto-pkcs11-lib','/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so');
        utils.setConfigSetting('crypto-pkcs11-pin','1234');
        utils.setConfigSetting('crypto-pkcs11-label','fabric');
        utils.setConfigSetting('crypto-pkcs11-slot',0);
        utils.setConfigSetting('crypto-pkcs11-usertype',1);
        utils.setConfigSetting('crypto-pkcs11-readwrite',true);
        utils.setConfigSetting('crypto-pkcs11-security',256);
        
        const hsmProvider = new HsmX509Provider({
    		lib: '/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so',
    		pin: '1234',
    		slot: 0
        });
        
        // Create a new CA client for interacting with the CA.
        const caURL = ccp.certificateAuthorities['ca.org1.example.com'].url;
        const ca = new FabricCAServices(caURL);

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        wallet.getProviderRegistry().addProvider(hsmProvider);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userIdentity = await wallet.get('appUser');
        if (userIdentity) {
            console.log('An identity for the user "appUser" already exists in the wallet');
            return;
        }

        // Check to see if we've already enrolled the admin user.
        const adminIdentity = await wallet.get('admin');
        if (!adminIdentity) {
            console.log('An identity for the admin user "admin" does not exist in the wallet');
            console.log('Run the enrollAdmin.js application before retrying');
            return;
        }

        // build a user object for authenticating with the CA
        const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
        const adminUser = await provider.getUserContext(adminIdentity, 'admin');

        // Register the user, enroll the user, and import the new identity into the wallet.
        const secret = await ca.register({
            affiliation: 'org1.department1',
            enrollmentID: 'appUser',
            role: 'client'
        }, adminUser);
        const enrollment = await ca.enroll({
            enrollmentID: 'appUser',
            enrollmentSecret: secret
        });
        const x509Identity = {
            credentials: {
                certificate: enrollment.certificate,
                ski: enrollment.key._ski.toString('hex'),
            },
            mspId: 'Org1MSP',
            type: 'HSM-X.509',
        };
        await wallet.put('appUser', x509Identity);
        console.log('Successfully registered and enrolled admin user "appUser" and imported it into the wallet');

    } catch (error) {
        console.error(`Failed to register user "appUser": ${error}`);
        process.exit(1);
    }
}

main();
