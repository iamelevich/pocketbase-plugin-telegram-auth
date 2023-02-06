import PocketBase, { Record, Admin } from 'pocketbase';
import { useEffect, useState } from 'react';
import usePB from './usePB';

export default function useTgWebAppAuth(): [string, Record | Admin | null, () => Promise<void>] {
    const pb = usePB();
    const [token, setToken] = useState('');
    const [record, setRecord] = useState<Record | Admin | null>(null);

    const renewAuth = () => {
        return pb.send('/api/collections/users/auth-with-telegram', {
            method: 'POST',
            body: {
                data: (window as any).Telegram.WebApp.initData
            }
        }).then(res => {
            pb.authStore.save(res.token, res.record);
        });
    }

    useEffect(() => {
        pb.authStore.onChange((authToken, authRecord) => {
            setToken(authToken);
            setRecord(authRecord);
        });
        renewAuth();
    })
    return [token, record, renewAuth]
}