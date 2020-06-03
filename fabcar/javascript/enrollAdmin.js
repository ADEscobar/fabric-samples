/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const FabricCAServices = require('fabric-ca-client');
const { Wallets, HsmX509Provider } = require('fabric-network');
const fs = require('fs');
const path = require('path');
const utils = require('fabric-common/lib/Utils');

async function main() {
    try {
        // load the network configuration
        const ccpPath = path.resolve(__dirname, '..', '..', 'first-network', 'connection-org1.json');
        const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
        const ccp = JSON.parse(ccpJSON);
        
        utils.setConfigSetting('crypto-hsm',true);
        utils.setConfigSetting('crypto-pkcs11-lib','/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so');
        utils.setConfigSetting('crypto-pkcs11-pin','1234');
        utils.setConfigSetting('crypto-pkcs11-label','fabric');
        utils.setConfigSetting('crypto-pkcs11-slot',0);
        utils.setConfigSetting('crypto-pkcs11-usertype',1);
	utils.setConfigSetting('crypto-pkcs11-readwrite',true);
        utils.setConfigSetting('crypto-pkcs11-security',256);
        
        // Create a new CA client for interacting with the CA.
        const caInfo = ccp.certificateAuthorities['ca.org1.example.com'];
        const caTLSCACerts = caInfo.tlsCACerts.pem;
        const ca = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify:false}, caInfo.caName);
        
        const hsmProvider = new HsmX509Provider({
    		lib: '/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so',
    		pin: '1234',
    		slot: 0
	});
        
        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        wallet.getProviderRegistry().addProvider(hsmProvider);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the admin user.
        const identity = await wallet.get('admin');
        if (identity) {
            console.log('An identity for the admin user "admin" already exists in the wallet');
            return;
        }

        // Enroll the admin user, and import the new identity into the wallet.
        const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
        const x509Identity = {
            credentials: {
                certificate: enrollment.certificate,
                ski: enrollment.key._ski.toString('hex'),
            },
            mspId: 'Org1MSP',
            type: 'HSM-X.509',
        };
        await wallet.put('admin', x509Identity);
        console.log('Successfully enrolled admin user "admin" and imported it into the wallet');

    } catch (error) {
        console.error(`Failed to enroll admin user "admin": ${error}`);
        process.exit(1);
    }
}

main();
