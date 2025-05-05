import { readFileSync, writeFileSync } from "fs";

let contractAddress = "0xae0127dd5433791a613c9dd1551cb52947cc08b9";
let selfAddress = "0x9dc012f381313c4f640c09d6cca249fce53d2a4b";

const endpoint = "http://10.10.5.12:8546";

function mapFn(f) {
    const obj = {
        "up": "0xd5a49e01",
        "down": "0xd8337928",
        "right": "0x1f2a63c0",
        "left": "0x16e64048",
        "win": "0x473ca96c",
        "getFlag": "0xf9633930",
    };
    return obj[f];
}

async function sendJson(json) {
    const response = await fetch(endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(json)
    });

    if (!response.ok) {
        throw response;
    }

    const data = await response.json();
    return data;
}

async function getAccounts() {
    const result = await sendJson({
        "jsonrpc": "2.0",
        "method": "eth_accounts",
        "id": 1
    });
    return result.result;
}

function numberToHex(num) {
    if (num < 0) {
        throw new Error("Negative numbers are not supported");
    }
    return "0x" + num.toString(16).padStart(64, "0");
}

async function getTransactionReciept(hash) {
    const result = await sendJson({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [
            hash
        ],
        "id": 1
    });
    return result.result;
}

async function initSelfAddress() {
    const accounts = await getAccounts();
    selfAddress = accounts[0];
    console.log("Self address:", selfAddress);
}

async function initContractAddress() {
    for (let i=0; i < Number.MAX_SAFE_INTEGER; i++) {
        const result = await sendJson({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [
                numberToHex(i),
                true
            ],
            "id": 1
        });
        for (const tx of result?.result?.transactions || []) {
            // Transaction with large payload will be the contract
            if (tx.input.length > 500) {
                const hash = tx.hash;
                const reciept = await getTransactionReciept(hash);
                contractAddress = reciept.contractAddress;
                console.log("Contract address:", contractAddress);
                return;
            }
        }
    }
}

async function readFunction(fn) {
    const body = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {
                "to": contractAddress,
                "data": fn,
            },
            "latest"
        ],
        "id": 1
    };
    return await sendJson(body);
}

const largeNumber = "0xFFFFFFFFFFFFFFF";

async function setBalance(value) {
    return await sendJson(
        {
            "jsonrpc": "2.0",
            "method": "hardhat_setBalance",
            "params": [
                selfAddress,
                value
            ],
            "id": 1
        }
    );
}

async function callFunction(fn) {
    const body = {
        "jsonrpc": "2.0",
        "method": "eth_sendTransaction",
        "params": [
            {
                "from": selfAddress,
                "to": contractAddress,
                "data": fn,
                "gas": "0x999999",
                "value": "0x0"
            }
        ],
        "id": 1
    };

    return await sendJson(body);
}

function isWall(obj) {
    return obj?.error?.message?.includes("Wall");
}

function isOOB(obj) {
    return obj?.error?.message?.includes("Out of bounds");
}

function isSuccess(obj) {
    return obj?.error === undefined;
}

function isError(obj) {
    return !isSuccess(obj);
}

function decodePosition(s) {
    return s.split(":").map(Number);
}

function encodePosition(pos) {
    return pos.join(":");
}

function getState() {
    try {
        return JSON.parse(String(readFileSync("state.json")));
    } catch (e) {
        return {
            position: [0, 0],
            map: {}
        };
    }
}

const state = getState();

function saveState() {
    writeFileSync("state.json",JSON.stringify(state, null, 2));
}

function add(a, b) {
    const [ax, ay] = a;
    const [bx, by] = b;
    return [ax + bx, ay + by];
}

async function win() {
    await callFunction(mapFn("win"));
}

async function flag() {
    const flagResult = await readFunction(mapFn("getFlag"));
    if (isSuccess(flagResult)) {
        const flagHex = flagResult.result;
        const flag = Buffer.from(flagHex.slice(2), "hex").toString("utf-8");
        console.log("Flag: "+JSON.stringify(flag));
    }
}

async function moveInternal(fn, diff) {
    await setBalance(largeNumber);
    const newPosition = add(state.position, diff);
    console.log("Moving from", state.position, "to", newPosition, fn);
    const result = await callFunction(mapFn(fn));
    if (isWall(result)) {
        state.map[encodePosition(newPosition)] = "W";
        console.log("Hit a wall at", newPosition, fn);
        saveState();
    }
    else if (isOOB(result)) {
        state.map[encodePosition(newPosition)] = "O";
        console.log("OOB at", newPosition, fn);
        saveState();
    }
    else if (isSuccess(result)) {
        state.map[encodePosition(newPosition)] = " ";
        state.position = newPosition;
        saveState();
    }
    else {
        state.map[encodePosition(newPosition)] = "E";
        console.log("Error:", result);
        saveState();
    }
    await win();
    await flag();
}

async function move(dir) {
    const [dx, dy] = dir;
    if (dx == 1 && dy == 0) {
        return moveInternal("right", dir);
    }
    if (dx == -1 && dy == 0) {
        return moveInternal("left", dir);
    }
    if (dx == 0 && dy == 1) {
        return moveInternal("down", dir);
    }
    if (dx == 0 && dy == -1) {
        return moveInternal("up", dir);
    }
}

async function handleKeyboardInput() {
    while (true) {
        process.stdin.setRawMode(true);
        const input = await new Promise((resolve) => {
            process.stdin.once("data", (data) => {
                resolve(data.toString().trim());
            });
        });
        const key = input.trim().toLowerCase();
        if (key === "w") {
            await move([0, -1]);
        }
        if (key === "s") {
            await move([0, 1]);
        }
        if (key === "a") {
            await move([-1, 0]);
        }
        if (key === "d") {
            await move([1, 0]);
        }
        if (key == "r") {
            await win();
            await flag();
        }
        if (key == "q") {
            console.log("Exiting...");
            process.exit(0);
        }
    }
}

async function explore() {
    while (true) {
        const dirs = [
            [1, 0],
            [0, 1],
            [-1, 0],
            [0, -1]
        ];
        let validDirs = dirs.filter((dir) => {
            const newPosition = add(state.position, dir);
            const key = encodePosition(newPosition);
            const val = state.map[key];
            return val === undefined || val === " ";
        });
        if (validDirs.length === 0) {
            validDirs = dirs;
        }
        const randomIndex = Math.floor(Math.random() * validDirs.length);
        const dir = validDirs[randomIndex];
        await move(dir);
    }
}

async function init() {
    await initSelfAddress();
    await initContractAddress();
}

async function main() {
    await init();
    const args = process.argv;
    if (args.includes("explore")) {
        await explore();
    }
    if (args.includes("play")) {
        await handleKeyboardInput();
    }
}

main();