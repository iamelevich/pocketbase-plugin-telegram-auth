import PocketBase from 'pocketbase';

let pb: PocketBase | undefined = undefined

export default function usePB(): PocketBase {
    if (!pb) {
        pb = new PocketBase('http://127.0.0.1:8090');
    }
    return pb;
}