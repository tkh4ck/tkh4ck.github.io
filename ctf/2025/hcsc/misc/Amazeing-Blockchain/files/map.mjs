import { readFileSync } from "fs";

function decodePosition(s) {
    return s.split(":").map(Number);
}

function encodePosition(pos) {
    return pos.join(":");
}

function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function equals(a, b) {
    return a[0] === b[0] && a[1] === b[1];
}

while (true) {
    try {
        await wait(100);
        const state = JSON.parse(String(readFileSync("state.json")));
        const positions = Object.keys(state.map).map(decodePosition);
        let min = [Infinity, Infinity];
        for (const position of positions) {
            if (position[0] < min[0]) {
                min[0] = position[0];
            }
            if (position[1] < min[1]) {
                min[1] = position[1];
            }
        }
        const max = [-Infinity, -Infinity];
        for (const position of positions) {
            if (position[0] > max[0]) {
                max[0] = position[0];
            }
            if (position[1] > max[1]) {
                max[1] = position[1];
            }
        }
        const width = max[0] - min[0] + 1;
        const height = max[1] - min[1] + 1;

        let output = "";

        for (let y = 0; y < height; y++) {
            const row = new Array(width).fill("?");
            for (let x = 0; x < width; x++) {
                const pos = [x + min[0], y + min[1]];
                const key = encodePosition(pos);
                if (key in state.map) {
                    row[x] = state.map[key];
                } else {
                    row[x] = "?";
                }
                if (equals(pos, state.position)) {
                    row[x] = "P";
                }
            }
            output += row.join("") + "\n";
        }
        console.clear();
        console.log(output);
    } catch(e) {
        console.clear();
        console.error(e);
    }
}