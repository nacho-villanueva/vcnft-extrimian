import {VCService, DIDService} from "vcnft/build"

import { DIDUniversalResolver } from '@extrimian/did-resolver';
import {
    KeyAgreementPurpose,
    AssertionMethodPurpose,
} from '@extrimian/did-core';
import { KMSClient } from '@extrimian/kms-client';
import { KMSStorage, LANG, Suite } from '@extrimian/kms-core';
import { CreateDIDResponse, Did } from '@extrimian/did-registry';

class SecureStorage implements KMSStorage {
    map = new Map<string, any>();

    async add(key: string, data: any): Promise<void> {
        this.map.set(key, data);
    }

    async get(key: string): Promise<any> {
        return this.map.get(key);
    }

    async getAll(): Promise<Map<string, any>> {
        return this.map;
    }

    async update(key: string, data: any) {
        this.map.set(key, data);
    }

    async remove(key: string) {
        this.map.delete(key);
    }
}

const storage = new SecureStorage();

const kms = new KMSClient({
    lang: LANG.es,
    storage: storage,
});


export const ExtrimianVCService : VCService = {
    createVC(params: any): Promise<any> {
        return Promise.resolve(undefined);
    }, signVC(params: any): Promise<any> {
        return Promise.resolve(undefined);
    }, verifyVC(params: any): Promise<any> {
        return Promise.resolve(undefined);
    }
}

export const ExtrimianDIDService : DIDService = {
    async createDID(params: any): Promise<any> {
        console.log(params)
        const [updateKey,
            recoveryKey,
            didComm,
            bbsbls] = await Promise.all([
            kms.create(Suite.ES256k),
            kms.create(Suite.ES256k),
            kms.create(Suite.DIDComm),
            kms.create(Suite.Bbsbls2020),
        ])

        const didService = new Did();

        return didService.createDID({
            recoveryKeys: [recoveryKey.publicKeyJWK],
            updateKeys: [updateKey.publicKeyJWK],
            verificationMethods: [
                {
                    id: 'bbsbls',
                    type: 'Bls12381G1Key2020',
                    publicKeyJwk: bbsbls.publicKeyJWK,
                    purpose: [new AssertionMethodPurpose()],
                },
                {
                    id: 'didComm',
                    type: 'X25519KeyAgreementKey2019',
                    publicKeyJwk: didComm.publicKeyJWK,
                    purpose: [new KeyAgreementPurpose()],
                },
            ],
        });
    },


    resolveDID(params: any): Promise<any> {
        return Promise.resolve(undefined);
    }
}