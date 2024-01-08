const chance = new Chance('fixed');

const portLabel = document.querySelector('.port-label');
const dockBtn = document.querySelector('.port-label button');

const cotd = document.querySelector('.cotd');
const cotdName = document.querySelector('.cotd h3');
const cotdDesc = document.querySelector('.cotd p.description');
const cotdImg = document.querySelector('.cotd img');
const closeFeeshBtn = document.querySelector('.cotd button.closefeesh');
const tweetBtn = document.querySelector('.cotd button.tweet');
const pescadexPrevBtn = document.querySelector('.cotd .pescadex button.prevBtn');
const pescadexNextBtn = document.querySelector('.cotd .pescadex button.nextBtn');
const pescadexFINdexSeeWhatIDidThere = document.querySelector('.cotd .pescadex span.findex');
const setBearingBtn = document.querySelector('button.setbearing');
const shortcutsMenu = document.querySelector('div.shortcuts');
const portlist = document.querySelector('div.shortcuts div.port-list');
const closeBearingBtn = document.querySelector('button.closeBearing');
const clearDestinationBtn = document.querySelector('button.clearBearing');
const ahoyBtn = document.querySelector('button.sayAhoy');

const settingsWindow = document.querySelector('.settings');
const settingsBtn = document.querySelector('button.settingsBtn');
const closeSettingsBtn = document.querySelector('button.closeSettings');
const saveSettingsBtn = document.querySelector('button.saveSettings');

let initialized = false;

const getJSON = async url => {
    return await fetch(url)
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then(jsonData => {
      return jsonData;
    })
    .catch(error => {
      console.error('Error fetching and parsing JSON:', error);
    });
};

let waveData;
(async () => {
    waveData = [];// await getJSON('assets/waves.json');
    
    waveData.forEach(wave => {
        Entities[`wave${chance.integer()}`] = wave;
    });
})();

let PORTS;

const wrapper = document.querySelector('.wrapper');
const raceName = document.querySelector('.msgbox-raceresults .racename');
const raceTime = document.querySelector('.msgbox-raceresults .racetime');
const raceHighscore = document.querySelector('.msgbox-raceresults .racehighscore');
const raceResultsClose = document.querySelector('.msgbox-raceresults button.closeResults');
const viewScoresBtn = document.querySelector('.msgbox-raceresults button.showScores');

raceResultsClose.addEventListener('click', () => {
    wrapper.classList.add('hidden');
});

viewScoresBtn.addEventListener('click', () => {
  const url = `highscores.html`;
  window.open(url, '_blank');
});

closeFeeshBtn.addEventListener('click', () => {
    cotd.classList.remove('visible');
});

setBearingBtn.addEventListener('click', () => {
  shortcutsMenu.classList.toggle('visible');
});

const initialCap = str => `${str.substr(0, 1).toUpperCase()}${str.substr(1)}`;

settingsBtn.addEventListener('click', () => {
    if (!playerData) return;
    if (!Entities[playerData.uid]) return;
    
    const me = Entities[playerData.uid];
    document.querySelector('.show-others').checked = me.showOthers;
    document.querySelector('.sail-group[x-sail="1"] span').innerText = initialCap(me.config.colors[0]);
    document.querySelector('.sail-group[x-sail="2"] span').innerText = initialCap(me.config.colors[1]);
    document.querySelector('.sail-group[x-sail="3"] span').innerText = initialCap(me.config.colors[2]);

    settingsWindow.classList.toggle('visible');
});

for (let sailIndex = 0; sailIndex < 3; sailIndex += 1) {
    document.querySelector(`.sail-group[x-sail="${sailIndex + 1}"] button.sailPrev`)
        .addEventListener('click', () => {
            const currentIndex = SailColors.indexOf(document.querySelector(`.sail-group[x-sail="${sailIndex + 1}"] span`).innerText.toLowerCase());
            let nextIndex = currentIndex - 1;
            if (nextIndex < 0) nextIndex = SailColors.length - 1;
            document.querySelector(`.sail-group[x-sail="${sailIndex + 1}"] span`).innerText = initialCap(SailColors[nextIndex]);
        });
    document.querySelector(`.sail-group[x-sail="${sailIndex + 1}"] button.sailNext`)
        .addEventListener('click', () => {
            const currentIndex = SailColors.indexOf(document.querySelector(`.sail-group[x-sail="${sailIndex + 1}"] span`).innerText.toLowerCase());
            let nextIndex = currentIndex + 1;
            if (nextIndex === SailColors.length) nextIndex = 0;
            document.querySelector(`.sail-group[x-sail="${sailIndex + 1}"] span`).innerText = initialCap(SailColors[nextIndex]);
        });
}

closeSettingsBtn.addEventListener('click', () => {
    settingsWindow.classList.remove('visible');
});

saveSettingsBtn.addEventListener('click', () => {
    if (!playerData) return;
    if (!Entities[playerData.uid]) return;

    const me = Entities[playerData.uid];

    const newSailColors = [
        document.querySelector('.sail-group[x-sail="1"] span').innerText.toLowerCase(),
        document.querySelector('.sail-group[x-sail="2"] span').innerText.toLowerCase(),
        document.querySelector('.sail-group[x-sail="3"] span').innerText.toLowerCase(),
    ];

    const updates = {};

    if (newSailColors.join('') !== me.config.colors.join('')) {
        updates.newSailColors = newSailColors;
    }

    const showOthers = document.querySelector('.show-others').checked;

    if (showOthers !== me.showOthers) {
        updates.showOthers = showOthers;
    }

    if (Object.keys(updates).length > 0) {
        socket.send(`prefs:${JSON.stringify({
            type: 'update_prefs',
            ...updates,
        })}`);
        settingsWindow.classList.remove('visible');
    }
});

pescadexPrevBtn.addEventListener('click', () => {
  pescadexIndex = pescadexIndex === 0 ? 0 : pescadexIndex - 1;
  updatePescadex();
});

pescadexNextBtn.addEventListener('click', () => {
  if (!playerData) return;
  pescadexIndex = pescadexIndex >= (playerData.fishCaught || []).length - 1 ? (playerData.fishCaught || []).length - 1 : pescadexIndex + 1;
  updatePescadex();
});

const showRaceResults = (name, time, position) => {
    raceName.innerHTML = `You completed ${name} in`;
    raceTime.innerHTML = `${time} seconds`;
    raceHighscore.innerHTML = `Scoreboard position: ${position}`;
    wrapper.classList.remove('hidden');
}

const __PARSE_URL_VARS__ = () => {
    let vars = {};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(m,key,value) {
        vars[key] = value;
    });
    return vars;
}

const UrlParams = __PARSE_URL_VARS__();

let pescadexIndex = 0;
let freshCatch = false;

const updateUI = () => {

    if (!playerData) return;

    const me = Entities[playerData.uid];

    if (me.race) {
        quitRaceBtn.style.display = 'block';
    } else {
        quitRaceBtn.style.display = 'none';
    }

    openpescadexBtn.style.display = playerData.canFish && playerData.fishCaught.length ? 'block' : 'none';

    const hasFishingPole = me.canFish;
    if (hasFishingPole && !me.fishing && !me.race && Math.abs(me.vx) < .001 && Math.abs(me.vy) < .001) {
        if (Math.abs(me.vx) < .001 && Math.abs(me.vy) < .001) castReelBtn.style.display = 'block';
    } else {
        castReelBtn.style.display = 'none';
    }

    if (me.fishing) {
        reelItInBtn.style.display = 'block';
        if (me.onTheLine) {
            reelItInBtn.classList.add('gotone');
            reelItInBtn.innerText = 'Reel it in!';
        } else {
            reelItInBtn.classList.remove('gotone');
            reelItInBtn.innerText = 'Reel it in';
        }
    } else {
        reelItInBtn.style.display = 'none';
    }

    if (me.bearing) {
      setBearingBtn.innerHTML = `<i class="fa-solid fa-compass"></i> ${PORTS[me.bearing].name}`;
    } else {
      setBearingBtn.innerHTML = '<i class="fa-solid fa-compass"></i> Set Bearing';
    }
};

const updatePescadex = () => {
  if (!playerData) return;

  if ((playerData.fishCaught || []).length) {
    const fish = playerData.fishCaught[pescadexIndex];

    cotdImg.setAttribute('src', `assets/fish/${fish.hash}.png`);
    pescadexFINdexSeeWhatIDidThere.innerText = `${pescadexIndex + 1} of ${playerData.fishCaught.length}`;
    cotdDesc.innerText = fish.description;
    if (freshCatch) {
      cotdName.innerText = `You caught a ${fish.name}!`
      freshCatch = false;
    } else {
      cotdName.innerText = fish.name;
    }
  }
};

closeBearingBtn.addEventListener('click', () => {
  shortcutsMenu.classList.remove('visible');
});

clearDestinationBtn.addEventListener('click', () => {
  Entities[playerData.uid].bearing = null;
  socket.send(`b:null`);
  updatePorts();
  shortcutsMenu.classList.remove('visible');
});

ahoyBtn.addEventListener('click', () => {
  socket.send(`ahoy!`);
  ahoyBtn.setAttribute('disabled', true);
  window.top.postMessage({
    type: 'sfx',
    filename: 'boat-bell.mp3',
  }, '*');
  setTimeout(() => {
    ahoyBtn.removeAttribute('disabled');
  }, 3000);
});

const updatePorts = () => {
  if (!playerData) return;
  
  const me = Entities[playerData.uid];

  const christmasPorts = Object.keys(PORTS).filter(port => PORTS[port].island === 'Christmas Island');
  const misfitPorts = Object.keys(PORTS).filter(port => PORTS[port].island === 'Island of Misfit Toys');
  const noirPorts = Object.keys(PORTS).filter(port => PORTS[port].island === 'Film Noir Island');
  const pixelPorts = Object.keys(PORTS).filter(port => PORTS[port].island === 'Pixel Island');
  const steampunkPorts = Object.keys(PORTS).filter(port => PORTS[port].island === 'Steampunk Island');
  const spacePorts = Object.keys(PORTS).filter(port => PORTS[port].island === 'Space Island');

  const sections = [
    [ 'Christmas Island', christmasPorts ],
    [ 'Island of Misfit Toys',  misfitPorts ],
    [ 'Film Noir Island',  noirPorts ],
    [ 'Pixel Island',  pixelPorts ],
    [ 'Steampunk Island',  steampunkPorts ],
    [ 'Space Island',  spacePorts ],
  ];

  let output = '';

  sections.forEach(([ sectionName, portArray ]) => {
    if (portArray.length) {
      output += `<h4>${sectionName}</h4>
      <ul class='ports'>`;
      portArray.forEach(portId => {
        output += `<li x-data='${portId}' ${me.bearing === portId ? 'class="selected"' : ''}>${PORTS[portId].name}</li>`;
      });
      output += `</ul>`;
    }

  });
  portlist.innerHTML = output;

  const portShortcuts = document.querySelectorAll('.shortcuts ul.ports li');
  portShortcuts.forEach(shortcut => {
      const me = Entities[playerData.uid];
      shortcut.addEventListener('click', event => {
          if (event.target.attributes['x-data'].value === me.bearing) {
              Entities[playerData.uid].bearing = null;
              socket.send(`b:null`);
          } else {
              Entities[playerData.uid].bearing = event.target.attributes['x-data'].value;
              socket.send(`b:${event.target.attributes['x-data'].value}`);
          }
          updateUI();
          updatePorts();
          shortcutsMenu.classList.remove('visible');
      });
  });
};

const websockHost = window.SEA_WS_HOST !== 'UNSET' ? window.SEA_WS_HOST : (window.SEA_WS_HOST === 'UNSET' ? 'ws://localhost:3000/sail' : '');
const socket = new WebSocket(`${websockHost}?dockSlip=${UrlParams.dockSlip}`);

const jstr = string => JSON.stringify(string);

const NS_PER_SEC = 1e9;

let blockData;
let isMaidenVoyage = true;
let playerData;

socket.addEventListener("message", event => {
  const messageType = event.data.substr(0, 2);
  const payload = event.data.substr(2);
  if (messageType === 'e:') {
    const parsed = JSON.parse(payload);
    Object.keys(parsed).forEach(id => {
      Entities[id] = {
        ...Entities[id],
        ...parsed[id],
      };
      
      if (typeof Entities[id].clockOffset === 'undefined') {
        Entities[id].clockOffset = Math.random();
      }
    });
  } else if (messageType === 'v:') {
    const parts = payload.split(':');
    for (let i = 0; i < parts.length; i += 5) {
        const [ uid, x, y, o, fishing ] = [
            parts[i],
            parts[i + 1],
            parts[i + 2],
            parts[i + 3],
            parts[i + 4],
        ]
        Entities[uid].x = x;
        Entities[uid].y = y;
        Entities[uid].o = o;
        Entities[uid].fishing = fishing === '1';
    };
    // Object.keys(parsed).forEach(id => {
    //   Entities[id] = {
    //     ...Entities[id],
    //     ...parsed[id],
    //   };
    // });
  } else if (messageType === 'p:') {
    const parsed = JSON.parse(payload);
    PORTS = parsed;
    updatePorts();
  } else if (messageType === 'z:') {
    const parsed = JSON.parse(payload);
    Entities[playerData.uid].port = parsed;
    if ((parsed || {}).id) {
      if (Object.keys(PORTS).indexOf(parsed.id) === -1) {
        PORTS[parsed.id] = parsed;
      }
    }
    updateUI();
    updatePorts();
  } else if (messageType === 'i:') {
    const parsed = JSON.parse(payload);
    playerData = parsed;
    
    if ((playerData.ports || []).length === 1) {
      document.querySelector('.overlay').style.display = 'block';
    } else {
      isMaidenVoyage = false;
    }
    Entities[playerData.uid] = playerData;
    updatePescadex();
    updatePorts();
  } else if (messageType === 'b:') {
    const parsed = JSON.parse(payload);
    blockData = parsed;
  } else if (messageType === 'k:') {
    const parsed = JSON.parse(payload);
  } else if (messageType === 'x:') {
    const parsed = payload;//JSON.parse(payload);
    if (Entities[parsed]) delete Entities[parsed];
  } else if (messageType === 't:') {
    try {
        const parsed = JSON.parse(payload);

        const notyf = new Notyf({
            position: {
                x:'center',
                y:'top'
            },
            duration: 5000,
        });
        notyf[parsed.type](parsed.message);
    } catch(err) {
        console.error(err);
    }
  } else if (messageType === 'm:') {
    const parsed = JSON.parse(payload);
    if (parsed.type === 'race_results') {
        if (parsed.data.time) {
            const trackName =  parsed.data.track;
            const finalTime =  parsed.data.time;
            const scoreboardPosition = parsed.data.scoreboardPosition;
            console.log(`${parsed.data.track} completed in ${finalTime} seconds`);
            showRaceResults(trackName, finalTime, scoreboardPosition);
        }
        const me = Entities[playerData.uid];
        delete me.race;
        delete me.raceIndex;
        delete me.raceTimes;
    }
  } else if (messageType === 'h:') {
    const parsed = JSON.parse(payload);
    HOTSPOTS = parsed;
  } else if (messageType === 'a:') {
    const parsed = JSON.parse(payload);
    const id = `ahoy${chance.integer()}`;    
    Entities[id] = {
      type: 'ahoy',
      id: parsed.id,
      x: parsed.x,
      y: parsed.y,
      dob: Date.now(),
      lifespan: parsed.lifespan,
    };
  } else if (messageType === 'f:') {
    const parsed = JSON.parse(payload);
    const idx = playerData.fishCaught.findIndex(fish => fish.name === parsed.fish.name);
    if (idx === -1) {
        playerData.fishCaught.push(parsed.fish);
        pescadexIndex = playerData.fishCaught.length - 1;
        freshCatch = true;
    } else {
      pescadexIndex = idx;
    }
    cotd.classList.add('visible');
    updatePescadex();
  }
  updateUI();
});

socket.addEventListener("open", event => {
    renderScene();
  });

let keyState = 0;
const WorldDimensions = {
    width: 2000,
    height: 2000,
};

const Keys = {
    UP: 1,
    RIGHT: 2, 
    LEFT: 4,
    DOWN: 8,
    ANCHOR: 16,
    BOOST: 32,
    w: 1,
    d: 2,
    a: 4,
    s: 8,
};

const isKeyPressed = targetKey => !!(keyState & targetKey);

const handleKey = event => {
    let oldKeyState = keyState;

    if (!initialized) {
      window.top.postMessage({
        type: 'init',
      }, '*');
      initialized = true;
    }

    if ([
        'ArrowLeft',
        'ArrowRight',
        'ArrowDown',
        'ArrowUp',
        'w',
        's',
        'a',
        'd',
    ].indexOf(event.key) !== -1){
        if (event.type === 'keydown') {
            if (event.key.indexOf('Arrow') === 0) {
                keyState |= Keys[event.key.replace('Arrow', '').toUpperCase()];
            } else {
                keyState |= Keys[event.key.toLowerCase()];
            }
        } else {
            if (event.key.indexOf('Arrow') === 0) {
                if (keyState & Keys[event.key.replace('Arrow', '').toUpperCase()]) keyState ^= Keys[event.key.replace('Arrow', '').toUpperCase()];
            } else {
                if (keyState & Keys[event.key.toLowerCase()]) keyState ^= Keys[event.key.toLowerCase()];
            }
        }    
    }

    if (event.key === 'b') {
        if (event.type === 'keydown') {
            keyState |= Keys.BOOST;
        } else {
            keyState ^= Keys.BOOST;
        }
    }

    if (event.key === ' ') {
        if (event.type === 'keydown') {
            keyState |= Keys.ANCHOR;
        } else {
            keyState ^= Keys.ANCHOR;
        }
    }

    if (oldKeyState !== keyState) {
        socket.send(`ks:${keyState}`);
    }
};


const raceShortcuts = document.querySelectorAll('.shortcuts ul.races li');
raceShortcuts.forEach(shortcut => {
    shortcut.addEventListener('click', event => {
        socket.send(`tp:${event.target.attributes['x-data'].value}`);
    });
});

document.addEventListener('keydown', handleKey);
document.addEventListener('keyup', handleKey);

const canvas = document.querySelector('canvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

setTimeout(() => {
    canvas.focus();
}, 10);

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    updateBgGradient();
});

const SailColors = [
    'white',
    'black',
    'green',
    'blue',
    'red',
    'pink',
    'yellow',
];

const BuoyRenderBuffer = 200;

const svg = `
<svg id="Layer_1" xmlns="http://www.w3.org/2000/svg" width="30000" height="30000" viewBox="0 0 2000 2000">
<path d="m856.12,1159.83c-1.63-1.33-3.1-3.19-5.02-3.99-29.19-12.11-56.27-27.49-78.24-50.69-4.68-4.94-8.37-10.83-13.11-15.7-7.26-7.46-10.42-17.52-16.34-24.81-2.26.88-4.19,2.28-6.04,2.18-2.42-.12-4.32-1.38-4.57-4.71-.18-2.45-2.07-4.77-3.49-7.76h5.55v4.26c1.35.35,2.85.74,4.35,1.13.33-.28.67-.56,1-.84-5.59-7.04-11.25-14.03-16.73-21.16-1.56-2.03-3.29-4.35-3.72-6.76-.71-3.98,2.97-7.17,7.23-6.92,1.15.07,2.29.69,3.41.64,1.64-.07,3.26-.51,4.89-.78-.77-1.48-1.49-2.99-2.33-4.43-.32-.55-.94-.93-.93-.92-2.48.16-4.47.3-6.46.43.33-1.58.65-3.17,1.19-5.75-2.6-2.27-6.18-5.48-9.83-8.6-3.24-2.76-5.09-6-2.67-10.04,2.4-4.02,6.14-4.13,10.08-2.45,2.38,1.01,4.69,2.16,7.6,2.51-.61-.81-1.09-1.8-1.86-2.4-6.69-5.16-13.37-10.34-20.2-15.31-3.81-2.78-6.06-8.95-4.21-12.73,1.9-3.88,5.72-5.13,11.23-3.37,2.52.8,4.93,2,7.32,3.15,12.91,6.19,25.8,12.42,38.06,18.33,2-1.47,3.76-2.77,5.52-4.07.37.38.75.76,1.12,1.14-.07,1.4-.14,2.79-.26,4.94,8.8,2.24,17.88,4.56,26.91,6.86.7-3.77,1.34-6.4,1.61-9.06.09-.95-.45-2.26-1.15-2.94-7.13-6.88-14.1-13.97-23.08-18.56-5.68-2.9-6.18-7.38-1.21-13.43-8.37-7.05-16.52-14.35-27.05-18.18-7.4-2.69-8.77-6.23-5.16-12.9-4.08-3.2-7.93-6.61-12.17-9.43-3.44-2.28-7.27-4.02-11.06-5.71-3.97-1.77-7.7-3.8-8.05-8.61-.37-5.02,2.76-7.93,8.09-10.15-3.83-4.53-7.36-8.81-11.02-12.97-1.75-1.99-4.49-3.44-5.44-5.69-1.03-2.44-1.59-6.24-.36-8.17,1.24-1.94,4.87-2.63,7.59-3.26,1.55-.35,3.37.52,5.61-.22-5.46-4.23-10.96-8.42-16.37-12.71-2.58-2.05-5.53-3.9-7.43-6.49-4.46-6.06-1.07-12.59,6.43-13.04,1.94-.12,3.89-.24,5.83-.36.21-.49.42-.98.62-1.47-4.73-2.78-9.43-5.6-14.2-8.32-2.15-1.23-4.6-2.01-6.59-3.44-3.8-2.75-4.73-6.8-3.71-11.16.99-4.28,3.95-6.97,8.23-7.78,3.5-.66,7.1-.82,11.03-2.3-6.62-3.66-13.25-7.31-19.86-10.98-1.75-.97-3.56-1.86-5.18-3-4.15-2.93-5.9-7.56-4.3-11.79,1.66-4.42,5.2-6.51,9.77-6.37,12.07.37,24.18.45,36.19,1.59,16.34,1.56,32.6,3.99,48.89,6.04.62.08,1.26.01,2.22.01-.72-4.42-.98-9.15,4.09-10.43,3.82-.97,8.07-.19,13.48-.19-2.69-1.21-4.4-1.94-6.07-2.74-2.24-1.08-5.05-1.71-6.52-3.46-1.96-2.34-3.88-5.53-3.96-8.41-.1-3.74,3.37-5.37,6.97-5.87.64-.09,1.27-.25,3.04-.6-3.12-1.67-5.53-2.67-7.61-4.15-2.73-1.95-5.88-3.86-7.54-6.59-1.28-2.1-1.64-6.22-.38-8,1.31-1.84,5.04-2.53,7.76-2.67,4.69-.25,9.48-.07,14.13.63,11.2,1.67,22.72,1.77,33.18,7.15,6.5,3.34,13.4,5.93,19.91,9.26,34.51,17.64,60.91,43.71,80.19,77.22,5.65,9.81,12.02,19.21,17.68,29.02,3.89,6.74,7.4,13.74,10.56,20.86,5.9,13.28,15.74,23.44,25.97,33.22,1.75,1.67,5.84,2.15,8.26,1.36,1.5-.49,2.57-4.37,2.67-6.78.77-17.96.16-36.06,2.11-53.88,2.17-19.85,1.85-39.51.89-59.33-.68-13.95-1.38-28.11.22-41.92,1.93-16.65,9.33-31.54,21.32-43.69,1.94-1.96,4.46-3.54,6.99-4.69,5.13-2.33,10.29-5.06,15.73-6.19,20.05-4.16,40.23-5.98,58.05,6.93,8.01,5.81,15.36,12.85,21.82,20.35,3.55,4.13,4.63,10.38,6.85,15.66.69,1.65,1.14,3.53,2.25,4.85,6.21,7.39,12.53,14.69,18.92,21.93,4.86,5.5,8.7,11.26,7.94,19.17-.47,4.91-2.35,8.68-6.83,10.8-4.1,1.94-7.32.12-11.06-2.02-7.42-4.25-15.38-7.57-23.18-11.16-3-1.38-6.5-1.91-9.16-3.72-9.01-6.18-19.24-4.22-28.86-3.88-4.08.14-9.23,4.4-11.74,8.2-6.32,9.55-12.16,19.58-16.84,30.02-6.16,13.73-7.03,28.65-3.33,43.06,3.75,14.61,8.69,29.03,14.49,42.95,8.76,21.04,19.72,41.2,27.92,62.44,9.65,24.98,18.52,50.56,16.25,78.08-1.05,12.74-3.43,25.38-5.05,36.96,1.83.94,3.52,1.81,5.22,2.69-.21.56-.41,1.13-.62,1.69h-4.96c-4.29,9.67-8.49,19.38-12.88,29.01-6.98,15.3-17.69,27.77-30.22,38.71-7.9,6.89-16.18,13.35-24.27,20.01-1.02.84-2.22,1.59-2.96,2.65-15.22,21.71-16.05,44.64-1.65,67.67,8.11,12.98,17.2,24.84,29.8,33.86,1.76,1.26,3.13,5.58,2.29,7.35-1.21,2.56-4.34,4.94-7.15,5.81-3.18.99-6.9.23-10.54.23-.52,1.34-.9,2.39-1.33,3.43-3.46,8.28-11.54,10.84-18.66,5.47-2.77-2.09-4.72-2.29-7.42-.32-2.68,1.96-5.56,3.68-8.47,5.28-4.01,2.19-8.97,3.62-12.01-.06-2.42-2.93-2.54-7.78-3.58-11.8-.14-.56.21-1.34.53-1.9,6.48-11.34,7.81-24.33,11.62-36.52,2.74-8.74,3.26-17.88,1.02-26.68-2.39-9.36-6.58-18.12-12.98-25.61-2.56-2.99-5.19-4.22-9.52-3.36-15.74,3.12-31.64,4.65-47.68,2.03-1.27-.21-3.45.07-3.94.88-4.78,7.91-10.63,15.33-10.74,25.37-.08,7.35,1.94,13.91,6.28,19.55,8.42,10.92,17.23,21.54,25.89,32.27.73.9,2.13,1.67,2.23,2.6.3,2.75,1.17,6.41-.19,8.11-1.36,1.7-5.46,2.55-7.79,1.86-7.22-2.16-7.62-2.29-9.06,4.62-.82,3.94-2.93,6.76-6.86,7.77-3.93,1.01-7.19-.39-9.83-3.4-5.19-5.91-6.71-6.08-12.46-.75-3.47,3.22-7.23,4.9-11.8,3.04-4.56-1.86-6.42-5.8-6.4-10.42.01-3.8.45-7.65,1.22-11.37,3.27-15.79,8.06-31.41,9.68-47.35,1.15-11.31-1.68-23.08-3.16-34.58-.48-3.74-3.23-5.72-7.45-5.95-4.12-.22-8.17-1.53-12.29-2.1-2.16-.3-4.4-.05-6.62-.05Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m461.28,408.6c4.13-1,8.07-2.87,11.68-5.08,2.67-1.64,6.37-4.23,6.6-7.7.21-3.15-2.91-5.46-2.95-8.62-.02-1.74,1.08-2.97,1.38-4.6.36-1.98-1.58-2.79-3.09-3.4-3.02-1.23-5.72-3.1-8.64-4.53-2.17-.62-4.34-1.26-6.51-1.9-6.91-2.05-13.75-4.53-21.01-4.84-7.12-.31-14.21.59-21.33.55-3.21-.02-6.36-.2-9.39-1.34-2.86-1.08-5.46-2.67-8.15-4.11-2.92-1.56-5.84-2.59-9.16-2.92-3.49-.35-7-.19-10.5-.31-5.75-.19-11.52-1.31-16.26-4.76-3.28-2.39-5.79-5.45-7.84-8.84-.17-.12-.32-.27-.44-.45-.83-1.15-1.73-2.23-2.37-3.5-.54-1.06-1.09-2.29-1.77-3.17-.26-.34-.74-.86-1.14-1.13-.29-.19-.45-.27-.7-.35-.13-.04-.27-.07-.4-.11-.05-.01-.08-.02-.11-.03-.02,0-.06,0-.11,0-.41-.03-.81-.04-1.22-.05-2.99.98-6.16.1-10.99-2.43-2.68-1.4-5.9-2.45-8.88-2.45-4.11,0-6.62,3.62-5.31,7.09,1.96,5.2,4.21,10.29,6.56,15.33,4.4,9.46,8.96,18.85,13.8,28.98,0,0,0,0,0,0,.55.66,1.03,1.37,1.49,2.1.45.72.88,1.45,1.37,2.15.07.1.25.46.36.5-.04-.05-.08-.1-.12-.16.04.05.08.11.13.16.06.08.13.15.2.23.04.05.1.09.14.14,2.14,1.5,4.63,2.58,7.01,3.41,4.88,1.7,10.02,2.64,15.13,3.29,6.95.89,14.09.19,20.76,2.67,2.86,1.07,5.07,3.01,7.05,5.29,1.95,2.25,3.77,4.6,6.45,6.01,6.53,3.43,14.46,2.99,21.54,2.03,7.81-1.06,15.49-2.79,23.37-3.4,4.12-.32,8.24-.46,12.35.1.35.05.69.12,1.03.17Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m479.56,378.2c-1.78-.42-3.56-.87-5.34-1.33.22.11.43.22.65.32.9.4,1.84.71,2.68,1.21,1.54.92,2.53,2.41,2.29,4.25-.24,1.86-1.69,3.29-1.31,5.25.33,1.73,1.54,3.19,2.22,4.78.69,1.61.88,3.31.28,4.98-1.27,3.57-4.66,6.01-7.81,7.85-2.52,1.47-5.18,2.81-7.95,3.81,2.45.5,4.89,1.05,7.36,1.45,7.38,1.21,14.55-.1,21.25-3.33,11.75-5.66,21.78-15.57,28.68-26.68-14.4,2.18-28.83.78-43.01-2.56Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m787.44,170.06c-3.41-2.75-6.82-.91-9.66,1.08-6.12,4.3-12.16,8.75-17.91,13.53-7.37,6.11-15.91,7.77-25.08,7.73-14.76-.07-28.47,2.41-36.51,16.74-2.99,5.34-5.63,10.98-7.58,16.77-3.48,10.34-8.29,19.88-15.05,28.41-14.47,18.24-31.5,33.81-50.11,46.97-2.22-.68-5.99-1.27-6.25-.57-.8,2.22-.3,4.91-.3,8.54-5.97,5.46-12.28,12.78-20.05,17.91-7.73,5.1-16,10.43-26.25,9.81-2.22-.13-4.78.57-6.73,1.68-9.01,5.1-18.02,3-27.09.5-2.08-.57-4.06-1.56-6.15-2.03-17.8-3.95-33.46-13.11-49.57-20.93-15.52-7.54-30.25-16.75-45.13-25.56-14.3-8.46-28.79-16.73-40.14-29.27-.99-1.1-2.24-2.02-3.49-2.81-9.69-6.12-19.3-12.4-29.23-18.12-2.18-1.26-6.18-1.58-8.16-.38-2.01,1.22-3.93,5.1-3.53,7.4,2.46,13.99,3.49,28.54,13.32,40.19,1.7,2.02,2.37,4.91,3.51,7.39-8.14-3.63-15.21-7.63-22-12.05-3.02-1.97-6.16-3.11-8.53-.43-1.95,2.21-3.48,5.7-3.39,8.57.11,3.68,1.72,7.44,3.2,10.94,3.21,7.54,6.54,15.03,9.89,22.54.31.45.64.89.94,1.36.29.46.53.93.75,1.42,0,.01.02.03.03.04.09.16.17.32.26.49.22.17.41.39.53.7,3.52,9.75,7.32,21.67,17.71,26.08,5.8,2.46,12.18,1.85,18.32,2.1,3.4.14,6.85.55,10.01,1.87,2.71,1.14,5.21,2.68,7.81,4.04,2.5,1.31,5.11,2.34,7.96,2.53,3.53.23,7.07.1,10.6-.07,6.9-.33,13.85-.87,20.71.29,3.48.59,6.87,1.73,10.25,2.74,3.35.99,6.7,1.99,10.05,2.97,6.38,1.85,12.8,3.62,19.3,4.98,13.38,2.81,27.07,3.61,40.56,1.02,1.32-.25,2.48,1.05,1.77,2.3-.83,1.49-1.72,2.94-2.66,4.36-8.06,12.2-19.81,23.43-33.78,28.41-3.3,1.18-6.75,1.93-10.24,2.15-4.29.27-8.53-.49-12.71-1.36-4.27-.89-8.52-1.86-12.92-1.84-4.35.02-8.7.38-13.02.94-7.73,1.01-15.34,2.92-23.15,3.33-7.05.37-15.15-.51-20.56-5.51-2.2-2.03-3.84-4.6-6.11-6.56-2.66-2.29-6.5-3.22-9.91-3.58-3.74-.39-7.5-.25-11.24-.68-2.49-.29-4.97-.62-7.44-1.04-5.39-.93-12.26-2.49-17.5-5.76-.25-.08-.49-.2-.69-.37-.1-.08-.18-.18-.27-.27-1.39-.97-2.64-2.08-3.68-3.34-1.08-.89-2.13-1.8-3.47-2.23-.69-.22-1.4-.36-2.12-.46-1.67.38-3.29.73-4.9,1.04-12.51,2.4-19.29,17.21-11.13,26.92,7.43,8.84,14.82,18.29,26.62,22.55,6.11,2.2,11.66,5.94,17.46,8.99-.13.51-.26,1.03-.39,1.54-6.11,1.37-11.74,5.58-17.91,2.83-1.63,1.16-2.84,2.4-4.32,3.01-10.32,4.32-21.48,5.3-32.24,4.91-9.55-.34-19.09-3.74-28.43-6.49-6.5-1.91-12.74-4.83-18.95-7.62-6.77-3.05-13.6-6.1-19.97-9.87-3.45-2.04-6.32-3.41-9.26-.17-2.98,3.29-1.48,6.32,1.22,9.2,5.91,6.31,11.77,12.67,17.48,19.16,4.26,4.84,3.76,8.96-2.15,11.76-7.34,3.48-15.21,5.35-23.56,4.49-5.7-.58-8.38,2.18-8.05,7.93.12,2.1.67,4.28,1.5,6.21,4.58,10.59,13.82,17.3,21.41,25.38,1.87,1.99,5.47,2.96,4.33,6.99-.06.22,2.6,1.28,4.05,1.81.69.25,1.67-.08,2.23.29,6.05,4.02,12.04,8.13,19.05,12.9-2.94.24-5.03.82-6.96.47-2.4-.43-4.66-1.63-6.99-2.46-3.63-1.3-7.13-1.33-9.08,2.56-1.87,3.74.19,6.16,3.42,8.16,2.52,1.56,4.66,3.72,7.03,5.53,8.05,6.15,16.06,12.36,24.21,18.37,6.47,4.77,13.12,9.27,19.69,13.89-2.44.87-4.86.1-6.76.79-2.19.8-5.12,2.63-5.49,4.47-.36,1.81,1.57,5.21,3.38,6.11,6.35,3.15,13.1,5.47,19.65,8.2,2.55,1.06,5,2.39,7.49,3.59-1.7.82-3.02.72-4.33.84-3.8.36-6.41,2.24-6.3,6.29.12,4.11,3,5.18,6.61,4.96,2.83-.18,5.67-.73,8.47-.51,5.31.41,11.14-3.14,14.5.35-2.34,3.3-4.58,6.49-6.86,9.65-1.05,1.46-2.17,2.88-3.26,4.32,1.76.84,3.49,2.31,5.28,2.39,6.61.29,13.24.11,19.86.11-2.05,2.12-4.58,2.97-6.6,4.5-1.44,1.09-2.17,3.1-3.22,4.71,1.88.41,3.84,1.35,5.64,1.11,4.69-.62,9.32-1.75,15.12-2.91-1.05,2.76-1.59,4.17-1.83,4.8-2.19-.83-3.93-1.48-5.66-2.14-.36.4-.73.81-1.09,1.21.8,1.67,1.59,3.33,1.82,3.81-.43,4.67-2.19,9.01-.75,11.48,2.28,3.92,6.86,1.44,9.87-.21,8.41-4.62,16.82-9.35,24.68-14.85,14.11-9.87,27.94-20.16,41.61-30.64,4.58-3.51,8.49-7.98,12.42-12.26,8.32-9.06,16.37-18.36,24.73-27.39,1.33-1.43,3.63-1.97,6.38-3.38-.13,13.16-2.34,24.79-6.92,35.25-4.37,9.97-8.78,20.34-17,28.39-4.31,4.22-3.97,8.46-.89,11.52,2.89,2.87,7.54,2.86,11.97.08,1.57-.98,3.28-1.73,5.25-2.76.36,1.39.65,2.01.66,2.63.12,4.32,1.35,8.1,5.94,9.35,4.63,1.26,8.2-.9,10.55-4.8,1.9-3.16,3.99-2.85,6.6-1.17,1.39.89,2.95,2.24,4.39,2.19,2.92-.1,6.34-.25,8.6-1.78,2.98-2.02,4.07-5.64,2.41-9.38-1.08-2.43-2.4-4.76-3.46-7.19-3.2-7.29-7.44-14.36-9.24-21.99-3.38-14.26-.99-28.77,1.01-43.06,1.34-9.58,3.67-19,14.64-22.58.74-.24,1.3-1.02,1.97-1.51,2.31-1.69,4.64-3.37,7.91-5.73,0,4.89.04,8.5-.02,12.12-.02,1.15-.43,2.3-.45,3.45-.06,2.77-.79,5.9.26,8.2.98,2.18,3.88,3.49,5.63,4.93-.71.94-1.61,2.13-3.28,4.34h7.53c-1-2.15-1.6-3.45-2.03-4.39,1.97-2.08,3.82-3.9,5.5-5.86,1.73-2.01,3.31-4.16,4.95-6.25.1.63.2,1.26.3,1.89,3.84,1.7,7.82,5.06,11.48,4.73,5.91-.52,5.57-6.9,6.64-11.64,3.46-.73,7.09-.92,10.18-2.32,2.56-1.16,5.68-3.41,6.34-5.79.58-2.1-1.51-5.35-3.16-7.53-1.94-2.57-4.67-4.55-6.37-6.14,1.55-1.95,3.43-3.3,3.56-4.8.1-1.16-2.26-3.71-3.03-3.53-1.85.43-3.41,2.11-4.66,2.99-3.87-3.62-8.11-7.57-12.56-11.72,6.04-8.91,12.37-17.46,17.83-26.53,5.91-9.81,11.31-19.96,16.36-30.23,5.2-10.56,9.78-21.42,14.51-32.19,5.81-13.22,11.5-26.5,17.26-39.74,4.62-10.61,6.59-22.39,14.13-31.72,3.66-4.53,6.74-9.59,10.75-13.78,7.1-7.43,14.29-14.88,22.2-21.41,11.01-9.1,22.78-17.26,34.1-26,8.94-6.9,17.38-14.47,26.57-21.02,17.21-12.25,31.76-26.72,42.14-45.33,5.81-10.41,12.57-20.3,18.68-30.55,3.04-5.1,5.81-10.38,8.28-15.78,1.95-4.26.77-8.28-2.87-11.21Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m564.95,1429.63c-19.23,11.39-37.01,24.08-47.51,44.51-.67,1.31-1.42,2.73-1.55,4.16-.59,6.27-.97,12.55-1.45,19.26,7.09-1.31,14.15-2.79,21.27-3.91,18.24-2.88,36.46-5.88,54.77-8.22,6.34-.81,12.97.77,19.38.23,23.06-1.95,40.59,9.12,56.77,23.46,13.21,11.7,26.64,23.2,39.21,35.57,11.53,11.34,20.64,24.53,27.91,39.23,7.06,14.29,15.91,27.7,23.96,41.5.84,1.44,2.21,2.9,2.25,4.38.08,2.61.13,5.94-1.33,7.68-1.3,1.55-5.07,2.42-7.06,1.69-4.14-1.51-7.84-4.24-11.69-6.52-2.24-1.33-4.43-2.75-7.61-3.38,1.53,3.2,3.44,6.29,4.45,9.65.63,2.08.76,5.5-.46,6.64-1.49,1.39-4.71,1.61-7.02,1.26-2.72-.41-5.24-2.03-7.89-3-3.56-1.3-4.55.64-4.38,3.73.04.81.75,1.67.6,2.39-.49,2.4-.55,5.87-2.07,6.8-1.6.98-4.91-.02-7.1-.98-3.54-1.55-6.78-3.78-10.15-5.72-.73,4.03-.36,7.94-2.13,9.93-1.43,1.61-5.46.91-8.04,1.2-.69,1.84-1.02,5.98-2.81,6.75-2.32.99-5.93-.32-8.72-1.35-2.59-.96-4.83-2.85-7.49-4.5-.15.64-.2,1.04-.34,1.4-.85,2.29-1.12,5.68-2.75,6.57-1.74.95-5.47.35-7.09-1.02-4.15-3.52-7.87-7.65-11.28-11.92-3.72-4.66-6.93-8.68-13.93-5.1-3.56,1.82-6.46-1.37-8.8-4.13-3.05-3.61-6.13-7.18-9.59-11.22-3.46,8.88-5.95,9.15-15.11,2.78-4.72,5.87-6.57,5.75-12.33.79-4.96-4.28-10.11-8.53-16.77-10.06-3.98,8.21-7.69,8.41-13.42,1.72-5.29-6.18-11.05-11.97-16.87-17.66-1.66-1.62-4.27-2.27-6.56-3.42-1.97,9.08-6.12,9.83-15.21,3.02-6.45,7.45-10.92.72-15.89-2.5-5.49,5.9-7.71,5.91-13.94.42-2.06-1.81-4.37-3.35-6.5-4.96-6.32,6.98-7.57,7.03-14.75,1.22-1.29-1.05-2.62-2.07-4-2.99-6.14-4.13-11.54-6.88-19.66-2.2-10.1,5.83-21.61,9.25-32.57,13.56-6.38,2.51-12.72,2.13-18.84-1.29-6.22,7.6-12.39,14.99-18.34,22.56-.85,1.08-1.03,3.06-.84,4.53.48,3.79,1.47,7.51,2.03,11.3.59,3.98-.65,7.37-4.4,9.21-3.88,1.91-5.98-.81-8.36-3.38-1.93-2.07-4.57-3.48-6.91-5.17-.4-.29-1.12-.35-1.29-.7-3.26-6.86-10.11-10.18-14.95-15.43-3.7-4.02-2.01-8.54,3.27-9.85,4.63-1.15,9.73-.68,14.17-2.24,6.52-2.3,12.95-5.26,18.77-8.95,2.83-1.79,4.29-5.82,6.21-8.94,3.63-5.9,2.21-10.82-3.85-13.66-5.81-2.73-9.23-7.46-11.02-13.08-4.5-.69-8.68-1.46-12.9-1.92-1.14-.12-2.63.35-3.55,1.07-6,4.75-11.84,9.7-17.83,14.48-4.44,3.54-4.17,8.8-5.16,13.58-.6,2.91-.79,5.91-1.28,8.85-.65,3.89-2.81,6.38-6.92,6.63-3.96.24-5.97-1.98-7.15-5.61-.45-1.38-2.17-2.34-3.31-3.49-1.88-1.91-3.81-3.76-5.61-5.74-1.87-2.07-3.23-4.83-5.48-6.26-3.25-2.06-5.88-4.24-5-8.26.91-4.18,3.93-6.21,8.3-6.58,6.4-.53,12.9-.82,19.11-2.25,9.29-2.14,15.04-9.09,19.78-16.87.43-.71.43-1.99.13-2.81-3.56-9.64-.51-18.63,3.72-26.9,4.75-9.29,10.99-17.82,16.34-26.82.76-1.27.83-3.75.08-4.98-2.24-3.65-4.91-7.07-7.68-10.36-2.75-3.27-3.26-6.31-.47-9.84.74-.93.93-2.59.8-3.85-.14-1.45-.84-2.87-1.44-4.24-3.79-8.69-3.64-9.21,4.96-14.77-1.24-1.81-2.16-4.05-3.82-5.36-2.51-1.99-5.34-4.12-3.53-7.22,1.24-2.12,4.55-3.03,7.73-4.97-1.37-4.27-10.82-10.31,1.3-15.62-2.54-2.3-4.94-4.1-6.85-6.3-2.05-2.37-5.28-5.33-5-7.67.29-2.45,4.14-4.48,8.69-7.51-2.54-1.84-5.14-3.6-7.61-5.53-6.41-4.99-6.56-6.88-.74-13.14-5.34-4.22-10.92-8.1-15.85-12.66-6.81-6.3-6.63-8.62-.05-15.11-5.98-4.8-11.84-9.73-17.94-14.32-3.87-2.91-5.81-5.98-3.14-9.84-2.96-4.23-6.81-7.72-8.06-11.98-1.85-6.28,6.55-5.68,9.01-9.97-2.29-1.58-4.77-2.61-6.18-4.45-1.58-2.05-3.42-5.16-2.89-7.23.53-2.07,3.63-3.97,6.02-4.93,2.97-1.2,6.35-1.35,10.85-2.2-3.2-3.77-5.57-6.64-8.01-9.45-6.58-7.56-5.69-11.24,3.83-14.42-2.07-3.21-4.38-6.21-6.06-9.53-2.33-4.58.65-8.75,5.63-7.97,9.48,1.49,19.14,2.47,28.34,5.05,11.46,3.22,22.65,7.53,33.72,11.94,13.59,5.41,27.02,11.25,40.38,17.2,19.42,8.65,35.79,20.33,39.81,43.17,1.94,11.02,2.03,22.01.66,33.26-1.68,13.82-1.61,27.85-2.29,41.79-.56,11.47-1.28,22.93-1.58,34.41-.13,4.93.62,9.88,1,15.21,1.79-.17,3.06-.22,4.31-.42,8.23-1.29,16.42-3.08,24.7-3.81,9.62-.84,14.84-7.47,20.34-13.89,13-15.16,25.59-30.83,43.14-41.07,8.13-4.74,16.71-9.11,25.6-12.06,12.25-4.07,25.49,3.32,28.65,15.53.81,3.15-.38,8.19-2.59,10.5-8.16,8.53-14.5,18.08-19.93,28.48-1.13,2.16-4.52,3.54-7.14,4.24-.69.18-2.85-3.4-3.57-5.51-1.21-3.54-1.8-7.29-2.74-11.32Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1623.59,902.4c.22-2.38.06-4.92.92-7.04.24-.59,4.29-.65,5.23.35,1.02,1.09.46,3.67.63,6.06,8.76-2.93,18.52-6.61,28.52-9.43,13.09-3.69,26.28-8.86,39.61-9.52,21.99-1.09,44.33-1.29,65.77,6.22,3.85,1.35,8.49,1.51,12.57.9,12.19-1.8,23.92-1.65,34.81,5,.99.61,2.08,1.09,2.99,1.8,2.67,2.11,5.49,4.36,3.71,8.3-1.65,3.66-4.94,3.37-8.2,2.7-.78-.16-1.58-.27-2.96-.5,1.21,8.86-.95,15.39-10.79,16.05-.13.69-.34,1.11-.21,1.29,5.16,7.12,3.95,10.08-4.71,11.36-2.79.41-5.59.68-8.36,1.01-.56,7.86-3.78,10.93-11.57,11.08-2.5.05-5,.03-7.5-.06-2.79-.1-5.18-.39-7.42,2.48-1.21,1.55-4.84,1.78-7.33,1.65-6.27-.31-12.51-1.16-18.71-1.8-1.32,7.74-2.66,9.17-10.19,9.11-10.48-.08-20.95-.81-31.43-.93-6.25-.07-12.51.5-20.45.85,28.13,33.72,36.53,70.56,26.46,112.19,3.73.54,7.06,1.02,10.39,1.49.66.09,1.39-.06,1.98.17,16.79,6.58,33.43,13.38,39.07,33.09,1.45,5.06,2.86,10.95-1.69,14.46-4.54,3.51-9.72.39-14.21-2.21-.97-.56-1.94-1.11-2.92-1.67-5.68,11.24-7.62,11.54-18.95,3.42-2.49,2.25-4.88,4.54-7.4,6.67-5.43,4.58-9.41,4.13-13.03-2.08-2.58-4.42-4.31-9.34-6.4-14.04-.86-1.94-1.67-3.9-2.14-5.01-5.75,2.83-10.92,6.81-16.58,7.75-5.66.94-11.83-1.16-19.4-2.14-5.16,4.69-13.31,6.21-22.12,5.54-1.24-.09-2.71.09-3.75.7-4.68,2.75-9.32,5.59-13.8,8.65-.96.66-1.71,2.4-1.69,3.62.23,14.85,1.18,29.69,6.94,43.58,2,4.81,5.31,9.23,8.67,13.3,6.56,7.96,13.59,15.53,20.37,23.31,1.19,1.37,2.3,2.89,3.11,4.51,3.11,6.2-.52,12.38-7.41,11.94-3.68-.23-7.46-1.64-10.82-3.26-6.29-3.04-9.5-2.51-13.49,3.16-4.4,6.24-9.22,7.2-15.18,2.54-2.92-2.29-5.38-2.11-8.11-.12-2.15,1.57-4.16,3.38-6.45,4.72-7.06,4.12-12.85,1.11-14.08-6.89-1.17-7.61,3.16-13.45,6.04-19.7,3.2-6.95,8.11-13.28,10.27-20.49,2.29-7.62,3.59-16.08,2.85-23.94-1.14-12.03-4.31-23.87-6.86-35.74-.32-1.47-1.79-3.31-3.17-3.85-13.85-5.45-23.02-16.38-31.62-27.59-5.74-7.48-10.32-15.93-14.78-24.29-6.5-12.17-8.64-25.44-8.28-39.14.41-15.75,3.21-31.08,7.8-46.14.54-1.78-.62-4.08-1.08-6.63-2.74,1.39-4.85,2.33-6.83,3.49-4.38,2.56-8.39,2.17-12.62-.63-1.37-.9-3.75-.62-5.59-.34-1.21.18-2.26,1.34-3.39,2.03-5.28,3.26-7.4,2.78-11.12-2.53-3.95,1.63-7.9,3.32-11.89,4.9-7.09,2.79-8.42,2.33-11.76-3.62-5.36,1.42-10.64,2.72-15.87,4.23-6.76,1.96-9.36-.22-8.31-7.59-3.45,0-6.87.18-10.26-.04-8.43-.55-10.57-4.11-7.3-11.83.38-.9.67-1.83,1.27-3.49-2.42-.6-4.68-.91-6.73-1.75-2.02-.83-4.41-1.77-5.62-3.41-5.57-7.55-3.88-12.33,4.83-16.11,21.37-9.27,44.05-12.24,66.92-14.61,20.52-2.12,41.11-4.1,60.58-11.76,1.97-.78,4.19-.96,6.87-1.54.44-6.49.91-13.09,1.31-19.7.49-7.98,1-15.96,1.34-23.95.12-2.8.27-5.77-.46-8.42-5.86-21.39-12.6-42.46-23.37-62.01-2.88-5.23-5.45-10.62-8.3-16.21-3.72,1.81-7.11,4.14-10.86,5.11-4.89,1.27-10.17,2.44-15.09,1.88-8.44-.95-11.61-9.63-6.76-16.64,4.72-6.82,9.5-13.6,14.1-20.5.85-1.28,1.38-3.07,1.33-4.61-.39-11.15,4.43-20.77,9.28-30.18,5.11-9.9,13.7-12.34,24.06-8.14,2.45.99,5.11,1.44,7.65,2.25,16.2,5.15,26.23,16.33,31.66,32.15,6.24,18.19,9.93,36.93,13.01,55.88,2.32,14.28,4.73,28.68,8.93,42.47,2.86,9.39,3.08,19.04,5.45,28.2,2.71,10.47,8.07,20.32,12.97,30.09.79,1.58,5.21,1.34,7.96,1.95-.29-.62-.57-1.25-.86-1.87Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1647.54,253.37c7.47-4.78,8.22-4.67,12.83,2.03,1.53-.12,3.17-.4,4.79-.35,5.39.17,9.32,4.65,8.11,9.69-2.21,9.2-6.22,17.31-15.62,21.25-9.04,3.79-18.07,7.67-27.28,11.01-10.15,3.68-12.7,12.43-15.03,21.34-.38,1.45.93,3.45,1.72,5.06,9.49,19.35,12.11,39.66,10.67,61.13-1.44,21.31-11.06,39.12-21.02,56.99-.97,1.75-3.97,3.37-5.93,3.27-1.63-.09-3.61-2.55-4.56-4.41-1.8-3.51-1.49-9.47-7.07-8.7-5.09.7-3.32,6.35-4.34,9.91-.23.8-.36,1.62-.54,2.44-.68,3.06-1.76,6.6-5.42,5.74-1.95-.46-3.59-3.68-4.67-5.98-1.19-2.54-1.57-5.46-2.31-8.22-.62-.05-1.23-.1-1.85-.16-1.31,3.22-2.68,6.42-3.91,9.68-.46,1.23-.21,2.96-1,3.77-1.23,1.26-3.29,2.87-4.6,2.57-1.25-.28-2.77-2.79-2.82-4.36-.74-20.61-4.45-40.32-15.65-58.16-5.92-9.43-10.81-19.53-16.95-28.8-5.2-7.86-11.03-15.44-17.46-22.33-10.75-11.53-33.36-10.98-42.87-2.71-8.42,7.32-17.41,14.09-25.09,22.12-15.82,16.55-35,27.71-56,35.62-7.14,2.69-15.96,3.48-23.45,2.1-11.29-2.07-19.21-14.04-20.32-25.82-.84-8.97,1.85-17.06,4.97-25.2,3.51-9.15,6.7-18.43,10.1-27.63.8-2.18,1.77-4.3,2.8-6.39,1.92-3.88,4.83-6.39,9.44-6.04,4.63.35,7.4,3.4,8.46,7.42,1.74,6.58,2.78,13.34,4.13,20.03.45,2.24.93,4.47,2.22,5.58,2.32.71,5.05.92,6.77,2.35.84.7-.2,3.67-.47,6.48,5.98,4.18,12.7.86,18.68-2.19,9.41-4.8,16.93-12.02,23.44-20.56,12.31-16.12,24.9-32.06,38.06-47.49,8.19-9.61,17.75-17.82,29.02-24.16,12.6-7.09,25.59-7.03,38.74-3.94,11.16,2.62,21.83,6.86,31.59,13.35,5.24,3.48,11.2,1.14,15.88-2.08,3.57-2.46,6.22-6.29,9.14-9.65,1.07-1.23,1.55-2.98,2.58-4.25,5.13-6.3,4.83-12.04.01-18.77-5.21-7.3-1.1-13.74,7.95-13.87,1.39-.02,2.96-.34,4.13-1.06,6-3.68,8.72-2.71,10.93,4.11.2.62.38,1.25.72,2.37,1.56-.87,2.85-2.02,4.3-2.3,2.13-.4,5.15-1.07,6.38,0,1.47,1.28,2.52,4.66,1.87,6.45-1.66,4.59-3.55,9.58-6.82,13.03-7.53,7.95-16.19,14.82-23.87,22.64-3.97,4.04-6.89,9.14-10.15,13.84-3.74,5.39-2.81,10.03,2.24,14.22,2.01,1.67,3.85,3.84,5.05,6.15,2.37,4.57,6.19,5.17,10.47,4.34,14.05-2.73,25.6-10.47,37.08-18.42-2.87-3.28-5.98-5.95-7.85-9.3-1.29-2.31-1.65-5.77-1.01-8.35.81-3.23,3.98-2.53,6.76-2.19.97.12,2.17-1.65,3.27-2.56.21-.56.42-1.11.62-1.67Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1413.03,1690.57c6.54-12.97,4.34-27.48-5.06-35.62-1.31-1.13-3.05-2.16-4.72-2.41-11.65-1.78-21.64-7.39-31.57-13.23-7.83-4.61-15.38-10.03-24.63-10.1-.56,2.33-.71,4.65-1.78,6.43-.32.53-4.03.1-4.68-.89-1.02-1.54-.75-3.93-1.15-6.86-1.34,0-3.57-.16-5.77.03-10.42.9-20.18-1.39-29.51-5.87-14.75-7.08-28.04-4.44-40.19,6.02-2.26,1.95-4.57,4.01-7.2,5.34-10.62,5.4-16.21,15.41-23.25,24.2-3.44,4.3-8.24,7.59-12.7,10.96-2.65,2-6.26,2.03-7.88-1.05-1.06-2.03-1.16-6.1.17-7.57,6.82-7.5,9.62-16.33,11.54-26.05,2.32-11.8,9.07-21.7,16.42-31.04,8.41-10.69,19.56-14.33,32.85-12.37,9.68,1.43,19.37,2.73,29.09,3.82,7.7.86,14.19-1.53,19.92-7.1,9.76-9.51,19.4-19.32,30.22-27.51,9.2-6.97,20.62-9.92,32.35-10.39,5.58-.22,11.17.11,16.75-.14,2.1-.09,4.17-1.09,6.08-1.63,4.24.46,8.61,1.1,13.01,1.37,14.91.92,29.07,4.97,43.19,9.56,9.3,3.02,18.98,4.87,28.38,7.59,7.49,2.17,14.83,4.87,22.02,7.25,1.42-1.34,2.95-2.77,4.47-4.2,1.2,1.58,2.08,3.72,3.67,4.63,4.96,2.84,10.09,5.53,15.46,7.37.64.22,3.56-3.23,6.17-.9-2.28,6.12-1.33,14.26-12.28,15.55,3.04,2.45,4.74,3.72,6.33,5.12,2.09,1.84,5.14,3.42,5.9,5.74,1.12,3.4-2.03,5.14-5.02,6.29-.9.35-1.64,1.1-2.44,1.66,4.62,9.73,2.1,14.42-8.63,15.11-9.64.63-17.88,4.67-26.06,9.19-4.22,2.34-8.32,5.09-12.83,6.65-6.34,2.2-8.57,7.13-9.68,12.75-1.79,9.13-3.18,18.34-4.49,27.56-1.36,9.56-6.35,17.47-11.48,25.22-3.78,5.71-10.41,5.02-16.25,5.82-.15.02-.33-.06-.49-.1-3.76-1.07-9.29-13.1-7.78-16.77.44-1.08.99-2.42.73-3.44-1.55-5.86-.1-8.23,5.79-9.43,4.38-.89,8.74-1.92,13.05-3.1,3.54-.96,5.65-3.29,5.91-7.13.36-5.42,1.29-10.85,1.11-16.24-.19-5.74-3.92-8.37-9.68-7.91-4.48.36-8.98.62-13.46,1.04-8.97.84-14.35,7.3-15.18,16.16-.94,10.07-2.41,20.16-4.72,30-2.05,8.73-9.35,12.98-18.3,12.84-4.62-.07-9.27.47-13.86,1.05-4.15.53-7.19-.94-9.34-4.34-2.11-3.33-1.83-6.49.64-9.7.9-1.17.91-3.06,1.2-4.64.12-.62-.43-1.6-.13-1.93,4-4.46,7.58-9.56,12.34-13,3.83-2.77,7.93.4,11.02,3.4,2.12,2.06,4.02,4.34,6.38,6.93Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1104.6,467.08c-6.95-3.33-7.15-4.38-3.7-9.39.85-1.24.42-3.59,1.42-4.44,2.26-1.91,4.88-3.71,7.66-4.6,3.14-1,5.63.25,6.88,3.9.35,1.01,3.03,1.35,4.71,1.76,2.21.54,4.48.83,6.73,1.24-.84,1.7-1.67,3.41-2.52,5.11-.43.86-.87,1.72-.98,1.94,2.68,2.83,5.05,5.34,8.13,8.59-8.39,3.09-13.62,8.11-16.45,15.61-7.7-3.39-15.16-4.3-21.91.32-6.36,4.36-12.29,9.4-18.08,14.51-3.85,3.39-8.3,3.67-12.36.14-3.4-2.96-6.99-5.71-10.81-8.81.86-.98,2.05-2.2,3.08-3.53,1.4-1.82,3.3-3.55,3.87-5.63,1.47-5.28,3.76-7.86,9.31-7.2,7.6.9,12.78-4.48,19.28-6.24,1.93-.52,4.22.14,6.31.49,1.86.31,3.99,1.77,5.4,1.21,1.59-.63,2.51-2.95,4.05-4.97Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m897.27,1445.65c-1.89,3.1-3.52,6.23-5.59,9.04-2.41,3.27-5.12,3.07-7.83.05-4.76-5.3-9.59-10.54-14.45-15.75-3.08-3.3-3.7-6.37-.1-9.86,1.47-1.43,2.63-3.51,3.17-5.5,1.26-4.7,5.23-5.93,8.92-6.79,1.71-.4,4.8,1.14,5.89,2.74,3.52,5.16,11.2,6.45,17.26,4.88,4.42-1.15,9.81.78,14.51,2.18.62.18-.1,5.47-.55,8.33-.25,1.6-1.31,3.06-1.88,4.62-.62,1.67-1.2,3.37-1.63,5.1-.63,2.52-.88,5.15-1.72,7.59-.52,1.53-1.97,4.07-2.74,3.98-4.57-.55-6.51,2.7-9.08,5.28-1.01,1.01-2.47,1.77-3.86,2.08-.48.11-2.01-1.61-1.88-2.28.25-1.39.98-3.28,2.07-3.83,2.73-1.36,3.21-2.81,1.84-5.48-1.1-2.15-1.7-4.55-2.34-6.36Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1362.24,1521.82c-5.31.3-9.58.27-13.75.9-1.84.28-3.46,1.9-5.2,2.89-1.16.66-2.34,1.27-3.51,1.91-.33-1.33-1.26-2.86-.89-3.94,1.19-3.43.54-5.16-3.35-5-3.77.15-3.07-3.11-4-5.19-.95-2.1-2.16-4.09-3.52-6-1.16-2.99-2.59-5.9-3.42-8.98-.76-2.84-2.24-6.79-1-8.58,2.28-3.29,6.43-3.48,10.65-2.07,4.68,1.57,9.76,1.96,14.46,3.49,1.82.59,3.69,2.65,4.47,4.49,1.64,3.89,3.54,6.45,8.35,5.91,1.49-.17,3.16,1.31,4.75,2.03-.9,1.52-1.58,3.21-2.73,4.51-3.14,3.58-3.89,7.49-1.31,13.63Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1393.23,834.47c-2.5,0-4.09-.06-5.67.04-.41.03-.76.62-1.18.87-12.65,7.62-14.81,6.42-24.22-4.43-.71-.82-1.62-1.53-2.07-2.47-.49-1.01-1.15-2.74-.7-3.26,3.5-3.99,6.69-7.85,6.37-13.79-.08-1.43,3.4-4.59,4.09-4.29,3.94,1.71,7.07-5.1,10.91-.81.17.19.65.07.97.15,9.46,2.41,10.43,3.8,12.01,13.11,1.08,6.35,3.18,12.52,4.43,18.85.35,1.78-.05,4.58-1.23,5.55-1.16.95-3.89.56-5.63-.07-.77-.28-1.3-2.68-1.07-3.95.27-1.51,1.48-2.86,2.99-5.51Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m547.7,1265.59c2.01-1.84,4.44-4.21,7.02-6.4,1.52-1.29,3.8-1.96,4.84-3.51,2.14-3.19,3.45-6.94,5.6-10.13.66-.98,3.87-1.67,4.28-1.16,2.07,2.55,3.79,5.44,5.27,8.4,1.63,3.27,3.29,5.47,7.59,4.15,2.97-.91,4.9,1.8,3.96,4.83-.69,2.22-1.23,4.48-1.83,6.72-.13.48-.12,1.19-.43,1.39-4.92,3.15-8.8,7.88-14.65,9.62-2.7.8-5.59,1.38-7.96,2.78-2.84,1.68-5.13,1.63-6.91-.95-1.99-2.86-3.7-5.95-5.22-9.09-.77-1.59-.85-3.5-1.55-6.64Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m976.8,455.01c3.9-3.33,5.47-2.79,6.79,2.42.77,3.04,1.71,6.08,3.02,8.91,2.57,5.5,1.62,8.89-3.84,11.77-3.07,1.62-6.21,3.11-9.58,4.8-.73-1.98-1.46-3.93-2.39-6.43-4.57,4.27-9.56,2.3-14.07.77-5.88-1.99-7.13-14.51-2.2-18.48.63-.51,1.44-.81,2.06-1.34,2.56-2.17,2.56-8.14,8.68-4.99,3.17,1.63,7.17,1.66,11.53,2.56Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1159.9,743.47c12.67-1.56,20.02-9.78,25.96-19.83,1.35-2.29,10.55-4.04,12.55-2.21.73.67,1.14,3.09.73,3.39-3.28,2.42-4.19,5.56-4.47,9.48-.1,1.43-3.05,2.48-4.2,4.06-1.78,2.45-3.14,5.19-4.64,7.84-.7,1.24-1.06,3.41-1.98,3.66-4.65,1.27-9.42,2.19-14.2,2.89-1.02.15-2.47-.92-3.33-1.81-2.14-2.23-4.06-4.68-6.43-7.46Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1257.49,937.51c.36-1.84.57-3.72,1.12-5.5.32-1.01,1.2-1.85,1.82-2.77.76.64,2.1,1.21,2.19,1.94.74,5.89,1.38,11.8,1.73,17.72.07,1.2-.89,2.86-1.9,3.65-3.47,2.72-11.88,1.27-13.9-2.56-1.69-3.2-3.36-3.98-6.57-2.09-2.49,1.47-4.02.25-4.45-2.55-1.04-6.8,2.49-13.32,8.72-16,4.34-1.86,6.38-1,8.04,3.46.56,1.51,1.04,3.05,1.55,4.58.55.04,1.1.08,1.64.11Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1216.39,1451.68c-.82.41-2.23.66-2.75,1.48-1.45,2.26-3.52,3.72-5.6,2.03-1.5-1.22-2.7-4.04-2.46-5.94.63-4.99-1.74-11.11,4.44-14.52.29-.16-.24-1.96-.5-2.96-.42-1.61-.93-3.2-1.42-4.88,9.38-1.46,15.86,3.53,16.87,11.96.34,2.84,1.54,5.59,2.48,8.34.86,2.52.53,4.27-2.47,4.67-.49.07-1.37-.03-1.42.15-2.59,8.58-4.62.57-7.16-.33Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1164.83,558.16c-3.22-1.55-6.45-3.09-9.67-4.64-2.68-1.29-6.89-1-6.09-5.95.04-.27-1.32-.67-1.92-1.15-.97-.8-2.52-1.63-2.65-2.6-.63-4.78-1.28-9.64-.92-14.39.07-1,4.32-1.69,6.65-2.52,1.75,5.11,6.94,5.48,10.75,7.71,2.73,1.6,2.81,3.62,1.98,6.33-.42,1.35-.19,3.01.13,4.45.87,3.95,1.94,7.85,2.92,11.77-.39.33-.78.65-1.17.98Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1135.59,1434.65c1.89.98,3.72,1.96,5.58,2.9,3.52,1.78,4.73,9.87,1.63,12.21-.71.54-2.49.23-3.44-.3-1.04-.58-1.68-1.87-2.52-2.89-4.1,4.81-9.96,6.6-12.53,3.62-1.4-1.64-2.65-4.36-2.34-6.33.71-4.42,3.33-7.74,8.3-8.33,1.73-.21,3.44-.56,5.32-.87Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m537.13,984.43c-.62-5.38.66-6.99,5.38-7.05-.4-2.69-.8-5.37-1.2-8.05-2.68.57-5.37,1.14-9.43,2.01,1.84-3.38,2.86-6.71,5.1-8.65.91-.79,4.45,1.45,6.41,2.16,1.54-.56,3.67-2.18,5.23-1.75,4.26,1.19,2.88,4.31,1.58,6.32,1.69,1.28,4.26,2.45,4.17,3.33-.17,1.59-1.82,3.12-3.09,4.45-.61.63-1.96.5-2.66,1.1-5.01,4.26-4.99,4.29-11.49,6.13Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1395.11,1040.1c4.66-5.61,6.83-13.69,15.28-17.21v21.41c-5.32,0-11.54,3.76-15.28-4.2Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1584.96,1279.55c0,9.44.11,18.88-.13,28.32-.03,1.28-2.12,3.71-2.8,3.56-1.95-.43-4.47-1.49-5.31-3.08-1.33-2.51-1.75-5.62-1.99-8.53-.09-1.07,1.23-2.55,2.28-3.33,1.13-.84,2.71-1.07,4.67-1.77-.37-2.68-1.24-5.44-.96-8.08.27-2.56,1.72-5,2.66-7.49.53.13,1.05.27,1.58.4Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1156.35,1416.31c2.48-.44,5.42.16,5.88,4.26.14,1.23-.74,2.76-1.54,3.87-.82,1.14-2.74,1.74-3.1,2.9-1.14,3.75-4.24,4.35-6.55,2.94-2.5-1.53-5.11-4.53-5.55-7.23-.29-1.79,2.92-4.48,5.04-6.17,1.06-.85,3.18-.37,5.82-.57Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1209.63,872.97c-2.47,1.33-3.86,1.82-4.92,2.7-3.38,2.81-5.69,2.49-7.56-1.75-.65-1.48-2.41-2.49-3.71-3.66-2.41-2.16-3.3-4.83-1.08-7.31,2.25-2.52,5.33-2.66,7.84-.17,3.16,3.13,6.05,6.52,9.42,10.19Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m847.7,1629.51h5.12c-.12.92-.17,2.06-.3,2.07-5.14.4-10.47,1.52-15.35.52-1.54-.32-1.89-6.37-2.79-9.8,3.03-.31,6.39-1.54,8.97-.61,1.79.64,2.5,4.27,4.35,7.83Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1335.91,1392.03c-1.38-2.05-3.32-4.23-4.27-6.77-.31-.82,1.73-3.02,3.13-3.86,2.08-1.23,4.54-2.42,6.86-2.48,1.88-.04,4.89,1.23,5.39,2.64.53,1.49-.85,4.26-2.21,5.69-1.72,1.82-4.26,2.88-6.47,4.22-.38.23-.9.22-2.43.56Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m428.19,1664.56c.65.55,2.38,1.82,3.83,3.36.65.69,1.11,1.98.96,2.89-.11.69-1.51,1.82-2.02,1.67-2.78-.79-6.66-1.18-7.87-3.13-1.33-2.14-.75-6.02.15-8.76.42-1.29,3.55-1.69,5.45-2.49-.13,1.67-.26,3.33-.5,6.47Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m462.04,1696.1c-1.81-2.05-3.94-4.48-6.08-6.9,2.51-1.84,4.86-4.06,7.64-5.26.73-.32,4.3,3.23,4.04,3.73-1.39,2.75.58,7.56-5.61,8.43Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m547.88,1225.94c3.34,3.25,2.52,8.02-2.25,11.99-1.75,1.45-3.78,2.64-5.86,3.58-.78.36-2.31-.04-2.98-.66-.39-.36-.08-2.11.47-2.77,3.37-4.04,6.9-7.94,10.61-12.15Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m470.77,1644.7c-.48.7-1.13,2.68-2.36,3.14-1.15.43-2.94-.66-4.37-1.26-.53-.22-.77-1.05-1.29-1.41-1.48-1.03-3.02-1.96-4.54-2.93,2.02-1.31,3.88-3.16,6.09-3.79,3.27-.92,6.96,2.45,6.46,6.24Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m860.45,1632.66c4.33-5.1,7.11-12.25,15.42-10.12-2.89,8.38-6.68,10.98-15.42,10.12Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m717.49,1072.34c1.07-.28,2.66-1.17,3.13-.76,3.57,3.1,8.22.54,11.88,2.5.99.53,1.65,1.66,2.46,2.51-.87.8-1.61,1.88-2.64,2.33-1.44.64-3.12,1.23-4.62,1.07-1.59-.16-3.33-.94-4.57-1.96-1.3-1.07-2.09-2.76-3.1-4.19-.85-.5-1.7-1-2.54-1.51Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m452.1,1668.11c-2.41-3.07-5.2-5.14-4.9-6.56.48-2.26,3.01-4.1,4.67-6.11,1.65,1.82,4.4,3.51,4.63,5.49.21,1.82-2.29,3.96-4.4,7.18Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1071.19,905.33c-1.23-1.13-2.26-2.08-2.96-2.72,1.71-3.23,3.21-6.07,5.28-9.98,1.86,2.05,3.45,3.79,5.03,5.53-1.42,1.03-2.95,1.94-4.21,3.14-1.13,1.07-1.95,2.47-3.14,4.03Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m307.87,260.92c-1.13,2.69-2.26,5.37-3.38,8.06-1.49-1.18-4.1-2.24-4.26-3.57-.46-4.07,3.25-4.37,5.91-5.45.58.32,1.15.64,1.73.96Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m450.51,1642.38c-.81.88-1.57,1.7-2.32,2.52-.74-.7-1.57-1.32-2.19-2.11-.76-.96-1.45-2.01-1.96-3.12-.55-1.2-.86-2.52-1.27-3.78,1.66.03,3.98-.6,4.84.25,1.39,1.38,1.82,3.72,2.91,6.24Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m518.25,1355.79c2.36-1.79,4.04-3.84,4.87-3.54,1.8.65,3.16,2.51,4.7,3.88-1.65,1.27-3.15,3.01-5.02,3.6-.78.25-2.33-1.94-4.55-3.94Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m759.57,1186.8c-2.28,1.7-4.21,3.86-4.92,3.52-1.8-.87-3.06-2.87-4.54-4.41,1.62-1.27,3.1-3.16,4.9-3.55.93-.2,2.43,2.27,4.56,4.44Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m500.17,596.69c2.46-2.25,4.49-4.68,4.94-4.42,1.79,1.05,3.08,2.94,4.55,4.52-1.4,1.07-2.72,2.8-4.24,3-1.23.16-2.71-1.5-5.26-3.1Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m570.69,706.22c-1.24,1.06-3.09,3.25-3.61,2.97-1.92-1.04-3.39-2.89-5.03-4.43,1.25-.92,2.49-2.56,3.76-2.58,1.57-.03,3.16,1.29,4.74,2.02.05.67.09,1.34.14,2.01Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m759.59,1113.46c-1.46-1.68-3.13-3.25-4.18-5.16-.18-.32,2.23-2.68,3.71-3.07,1.06-.28,3.67,1.15,3.68,1.83.02,2.05-.9,4.11-1.46,6.17-.58.08-1.17.15-1.75.23Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m705.63,939.47c1.92,2.85,3.56,4.5,4.05,6.44.16.61-2.78,2.87-4.2,2.78-1.23-.08-3.16-2.37-3.23-3.76-.07-1.43,1.73-2.96,3.38-5.46Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1636.48,1503.3c2.04,2.43,4.44,4.14,4.19,5.25-.38,1.69-2.59,2.96-4.03,4.41-1.19-1.55-2.9-2.96-3.38-4.71-.26-.97,1.54-2.49,3.22-4.95Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1343.76,1565.39c-1.68-2.42-3.52-3.92-3.45-5.33.07-1.4,1.98-3.66,3.25-3.78,1.36-.13,4.29,2.14,4.14,2.75-.49,1.95-2.11,3.61-3.93,6.36Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m505.61,797.43c.79,1.58,2.54,3.48,2.14,4.67-.52,1.56-2.73,2.57-4.21,3.81-.85-1.29-2.38-2.59-2.36-3.86.02-1.55,1.36-3.08,2.12-4.61.77,0,1.54,0,2.31,0Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1414.07,901.52c-.98-1.76-2.44-3.44-2.74-5.3-.14-.87,2.34-3.19,2.97-2.96,1.74.62,4.04,2.02,4.38,3.5.3,1.32-1.72,3.18-2.71,4.8-.63-.01-1.26-.03-1.89-.04Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1647.54,1189.89c3.36,1.3,5.48,1.88,7.24,3.02.3.2-.52,3.39-1.55,4.06-1.27.82-4.61.95-4.8.48-.74-1.84-.58-4.04-.89-7.55Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1312.96,1663.57c.68,1.37,2.25,3.18,1.84,4.03-.83,1.72-2.74,2.92-4.2,4.33-.86-1.31-2.58-2.76-2.39-3.9.27-1.67,1.9-3.11,2.95-4.66.6.06,1.2.13,1.81.19Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m282.89,192.65c3.05-2.89,5.82-3.48,7.66-.08.57,1.05-.63,4.35-1.76,4.8-4.17,1.69-4.38-2.34-5.9-4.72Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m584.53,1467.3c-2.74,1.62-4.3,3.13-6.02,3.34-1.02.12-3.44-2.26-3.25-2.72.72-1.78,2.01-4.17,3.52-4.53,1.24-.29,3.08,1.98,5.75,3.91Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m542.48,1354.63c-2.02,1.54-3.65,3.44-4.31,3.15-1.62-.72-2.8-2.44-4.16-3.76,1.39-1.32,2.78-2.64,4.17-3.96,1.17,1.24,2.34,2.48,4.3,4.57Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m661.05,354.68c-2.07-1.05-4.26-1.95-6.13-3.29-.4-.28.02-2.89.66-3.19,1.48-.7,4.24-1.44,4.81-.76,1.25,1.49,1.47,3.85,2.11,5.86l-1.45,1.37Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m246.44,1296.24c-1.87-3.02-2.72-5.88.37-7.91.83-.55,4.07.71,4.59,1.87,2.19,4.85-2.56,4.35-4.96,6.05Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1281.53,1559.24c1.69-.91,3.31-2.33,5.08-2.53,1.01-.11,2.99,1.65,3.16,2.78.19,1.23-1.37,3.93-1.9,3.86-2.1-.27-4.1-1.36-6.14-2.15-.07-.65-.14-1.31-.21-1.96Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m643.63,1021.93c.79-2.36-.81-6.65,4.11-5.68,1.32.26,2.15,2.99,3.21,4.58-2.12.97-4.24,1.94-6.36,2.92-.32-.61-.64-1.21-.96-1.82Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1414.88,795.49c1.5,2.68,3.2,4.36,2.89,5.5-.47,1.71-2.34,3.04-3.61,4.54-1.05-1.41-2.99-2.86-2.93-4.21.08-1.62,1.87-3.16,3.65-5.82Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m769.11,1247.6c-1.03-1.55-2.89-3.13-2.85-4.66.04-1.32,2.22-2.59,3.45-3.88,1.09,1.24,2.91,2.4,3.07,3.75.18,1.45-1.2,3.09-1.91,4.65-.59.05-1.18.09-1.77.14Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1479.56,361.88c-3.22,1.51-4.92,2.88-6.63,2.89-.97,0-2.74-2.24-2.7-3.42.04-1.14,2.07-3.24,2.98-3.12,1.72.23,3.26,1.76,6.35,3.65Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m207.3,1368.72c2.07-2.26,3.12-3.4,4.17-4.54,1.5,1.49,3.18,2.87,4.33,4.59.19.29-1.91,3.03-2.87,2.98-1.55-.08-3.04-1.53-5.63-3.03Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1615.04,1151.27c-.55,2.77,1.62,6.49-3.14,6.56-1.28.02-3.73-2.04-3.68-3.06.17-3.77,3.09-4.07,6.82-3.5Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m524.25,1297.82c-2-2.13-3.21-3.43-5.48-5.85,3.1-.8,5.19-1.55,7.33-1.76.54-.05,1.97,1.94,1.76,2.39-.86,1.77-2.21,3.29-3.61,5.23Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m676.4,1173.84c-2.05,1.67-3.84,3.65-4.27,3.39-1.6-.98-2.76-2.68-4.08-4.11,1.34-1.15,2.63-3.07,4.05-3.19,1.11-.09,2.4,2.08,4.3,3.91Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m531.41,650.88c-2.57,1.41-4.25,3.09-5.64,2.87-1.39-.21-2.49-2.32-3.72-3.59,1.5-1.04,2.94-2.76,4.52-2.9,1.18-.11,2.54,1.81,4.83,3.62Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m832.91,1178.57c-1.81-1.99-3.84-3.36-3.65-4.19.38-1.61,2.03-2.92,3.16-4.35,1.4,1.44,3.07,2.73,4.01,4.42.24.44-1.79,2.14-3.53,4.12Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m427.85,1751.08c1.93-3.09,4.37-4.35,7.26-2.13.68.53.46,3.74-.42,4.52-3.33,2.98-4.89-.21-6.84-2.39Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1736.79,999.38c-2.24,1.63-3.65,3.46-4.94,3.38-1.34-.08-2.56-2.01-3.83-3.13,1.52-1.2,2.91-2.77,4.63-3.4.69-.25,2.14,1.57,4.14,3.15Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m891.23,642.49c-2.37,1.63-3.61,2.97-5.12,3.42-2.8.83-4.02-1.28-3.93-3.52.04-1.13,1.91-3.22,2.63-3.1,1.86.33,3.54,1.66,6.42,3.2Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1249.46,1435.48c1.63,2.52,3.05,3.9,3.33,5.49.14.82-2.27,3.02-2.66,2.83-1.56-.76-3.3-2-3.9-3.5-.32-.79,1.58-2.47,3.23-4.82Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m518.54,653.85c-2.33,1.87-3.61,3.61-5.11,3.84-.96.14-2.26-1.96-3.4-3.05,1.29-1.21,2.42-2.84,3.95-3.45.77-.3,2.28,1.26,4.56,2.66Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1856.75,1022.94c.75,1.45,2.25,3.03,2.03,4.32-.23,1.38-2.08,2.48-3.22,3.71-.85-1.32-2.3-2.61-2.38-3.98-.07-1.33,1.27-2.73,1.99-4.1.53.02,1.06.04,1.58.06Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1349.28,261.8c-2,1.82-3.45,3.99-4.37,3.78-1.51-.33-2.68-2.21-3.99-3.43,1.34-1.05,2.56-2.58,4.08-2.96.92-.23,2.28,1.32,4.28,2.6Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m482.92,1223.6c-2.05,1.86-3.32,3.38-4.93,4.21-.41.21-2.53-1.65-2.86-2.83-.78-2.78,1.31-3.87,3.61-3.84,1.1.02,2.18,1.23,4.18,2.47Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1529.33,1640.48c-1.84,1.63-3.22,3.5-3.84,3.28-1.61-.59-2.89-2.1-4.3-3.24,1.14-1.36,2.28-2.71,3.42-4.07,1.34,1.14,2.67,2.28,4.71,4.03Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1662.49,417.92c-1.31.69-2.71,2.05-3.91,1.89-1.28-.17-2.37-1.77-3.54-2.75,1.15-1.02,2.2-2.67,3.49-2.88,1.19-.19,2.62,1.16,3.95,1.83l.02,1.9Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m384.88,1718.74c-1.62-1.15-3.65-2.04-4.67-3.58-.43-.65,1.28-2.7,2.01-4.12,1.62,1.7,3.23,3.39,4.85,5.09-.73.87-1.46,1.74-2.19,2.61Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1366.74,1531.16c-5.47.29-6-3.02-5.34-7.25,5.38-.2,6.64,1.46,5.34,7.25Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m338.2,1418.79c1.67,1.61,3.68,3.09,3.49,3.46-.73,1.43-2.15,2.51-3.31,3.72-1.11-1.07-2.75-1.99-3.13-3.28-.22-.77,1.53-2.12,2.95-3.9Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1240.04,912.93c1.4,1.63,2.81,3.26,4.21,4.9-1.02.63-2.84,1.89-2.93,1.78-1.29-1.62-2.34-3.43-3.46-5.19.73-.5,1.45-.99,2.18-1.49Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m659.22,1046.67c1.18-1.88,2.35-3.76,3.53-5.64,1.03.89,2.07,1.78,3.1,2.67-1.47,1.49-2.94,2.97-4.41,4.46-.74-.49-1.48-.99-2.22-1.48Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m797.72,1246.53c-1.1-1.82-1.97-3.24-2.92-4.8,2.76-1.01,5.16-1.88,7.56-2.76.33.34.65.68.98,1.02-1.73,2.01-3.46,4.03-5.63,6.55Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m811.23,1232.39c-2,1.19-3.2,2.45-4.36,2.42-.96-.02-1.88-1.57-2.82-2.44,1.21-1.11,2.29-2.48,3.71-3.16.41-.2,1.77,1.58,3.48,3.18Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m576.18,772.88c-2.34,1.82-3.67,3.12-5.26,3.84-.31.14-2.45-2.12-2.3-3.01.19-1.05,1.85-2.29,3.08-2.56,1.01-.23,2.31.83,4.48,1.73Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m716.39,1037.97c-5.45-.7-2.55-4.85-3.43-7.47,4,.07,4.52,1.27,3.43,7.47Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m809.62,1182.49c-1.17-1.6-2.35-3.2-3.52-4.81,1.41-.51,2.83-1.02,4.24-1.54l1.73,4.98c-.82.45-1.63.91-2.45,1.36Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m590.21,1372.81c.46,1.91.93,3.82,1.39,5.73-1.27.22-2.55.45-3.82.67-.18-2.02-.37-4.04-.56-6.06.99-.12,1.99-.23,2.98-.35Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m743.59,1136.18h-5.84c.14-1.29.28-2.58.43-3.87,1.87.3,3.73.59,5.6.89-.06.99-.12,1.98-.18,2.98Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m709.55,1035.88c1.55,2.02,3.12,3.19,3.17,4.44.04.84-1.97,2.17-3.26,2.47-.56.13-2.17-1.77-2.23-2.82-.07-1.06,1.18-2.2,2.32-4.08Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1647.54,253.37c-.21.56-.42,1.11-.62,1.67-2.02-.6-4.03-1.2-6.05-1.8,0-.63,0-1.27,0-1.9,1.84-.39,3.67-.96,5.51-1.02.36-.01.78,1.98,1.17,3.04Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1399.39,959.64c-2.41,1.54-3.72,2.68-5.22,3.13-.38.11-2.1-2.09-1.96-3.04.14-.99,1.73-2.34,2.81-2.46,1.03-.12,2.22,1.13,4.38,2.37Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1403.36,404.11c3.27-1.65,5.04-2.54,6.81-3.43.38.26.77.51,1.15.77-.61,1.8-1.23,3.61-1.84,5.41-1.59-.72-3.18-1.43-6.11-2.75Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1234.83,1517.05c.54-1.92,1.08-3.83,1.62-5.75,1.16.56,3.38,1.45,3.32,1.63-.57,1.82-1.51,3.53-2.35,5.27-.86-.38-1.73-.77-2.59-1.15Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m214.18,1235.57c.25-1.65.5-3.29.74-4.94,1.75.39,3.49.78,5.24,1.18,0,.47,0,.95-.01,1.42-1.39.96-2.78,1.92-4.17,2.87-.6-.18-1.2-.35-1.79-.53Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1474.54,772.42c1.19,1.36,2.37,2.71,3.56,4.07-1.02.82-2.04,1.63-3.06,2.45-.84-1.74-1.68-3.49-2.52-5.23.67-.43,1.35-.86,2.02-1.29Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1580.24,1593.72c1.1-1.55,2.19-3.09,3.29-4.64.87,1,2.65,2.57,2.44,2.92-.86,1.41-2.33,2.45-3.57,3.62-.72-.63-1.43-1.27-2.15-1.9Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1403.38,1661.58c1.2-1.23,2.27-2.69,3.7-3.52.37-.21,1.88,1.54,2.87,2.39-1.55,1.12-3.1,2.24-4.65,3.36-.64-.74-1.29-1.49-1.93-2.24Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1462.87,345.39l5.07,2.75c-.85.95-2.23,2.83-2.46,2.7-1.52-.86-2.78-2.16-4.13-3.32.51-.71,1.02-1.42,1.52-2.12Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m474.14,744.33c-1.94.43-3.87.87-5.81,1.3-.07-1.29-.14-2.59-.22-3.88h5.78l.25,2.58Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1715.46,1217.03c.19,1.8.37,3.6.56,5.4-1.49-.15-2.99-.31-4.48-.46.46-1.74.92-3.47,1.38-5.21.85.09,1.7.18,2.54.26Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m462.61,1423.51c1.36-.73,2.71-1.46,4.07-2.19.66,1.47,1.31,2.94,1.97,4.41h-5.66c-.13-.74-.25-1.48-.38-2.22Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m212.04,557.83c1.62.65,3.25,1.31,4.87,1.96-.54,1.15-1.08,2.31-1.63,3.46-1.49-1.11-2.99-2.21-4.48-3.32.41-.7.82-1.4,1.23-2.11Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m813.48,1196.49c1.82.55,3.64,1.1,5.46,1.66-.55,1.25-1.1,2.51-1.65,3.76-1.57-1.02-3.14-2.05-4.71-3.07.3-.78.6-1.56.9-2.35Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m275.58,1372.3c1.37,2.49,2.59,3.71,2.43,4.71-.17,1.09-1.62,1.98-2.51,2.95-.83-.82-2.35-1.68-2.32-2.47.05-1.31,1.11-2.57,2.39-5.2Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1529.45,917.38c.46-1.76.93-3.52,1.39-5.28l3.91,1.33c-.98,1.68-1.97,3.35-2.95,5.03l-2.36-1.08Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1607.76,1569.38c-1.91-.14-3.85-.19-5.71-.57-.17-.04.09-2.2.16-3.38,1.97.39,3.93.77,5.9,1.15-.11.93-.23,1.86-.35,2.8Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m348.86,215.81c-1.29.36-2.79,1.3-3.83.94-1.5-.52-2.66-2-3.96-3.07,1.01-.68,1.98-1.8,3.05-1.9,1.03-.1,2.15.86,3.24,1.35.5.89,1,1.79,1.5,2.68Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m922.04,666.61c1.03-1.65,2.06-3.29,3.09-4.94.79.85,2.41,2.19,2.24,2.48-.85,1.47-2.18,2.67-3.33,3.96-.67-.5-1.33-1-2-1.5Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m620.95,1650.25c-1.89.81-3.12,1.83-4.01,1.59-1.11-.3-1.95-1.63-2.9-2.51,1.07-.77,2.17-2.18,3.19-2.13,1.03.05,2,1.56,3.71,3.06Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m561.41,599.58c-1.11-1.56-2.22-3.12-3.33-4.68,1.01-.61,2.01-1.21,3.02-1.82.79,1.78,1.58,3.56,2.37,5.34-.69.39-1.37.77-2.06,1.16Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1138.43,898.37c1.32,2.4,2.55,3.63,2.38,4.62-.19,1.08-1.68,1.94-2.6,2.89-.73-.92-2.04-1.82-2.06-2.75-.02-1.14,1.03-2.31,2.27-4.76Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m708.99,1121.9c1.83-.36,3.67-.72,5.5-1.08l.95,1.07c-.74,1.34-1.34,3.65-2.26,3.79-1.34.2-2.91-1.17-4.39-1.87l.2-1.91Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/><path d="m1546.14,1157.21c-.68-1.51-1.87-3.05-1.81-4.53.03-.73,2.39-1.36,4.94-2.68-.52,3.27-.81,5.13-1.11,6.99-.68.07-1.35.15-2.03.22Z" style="fill:none; stroke:#545448; stroke-miterlimit:10; stroke-width:.75px;"/>
</svg>`;

const img = document.querySelector('img.svgref');

img.src = `data:image/svg+xml;base64,${window.btoa(svg)}`;
const ImageAssets = {
    ship: 'assets/ship.png',
    rod: 'assets/rod.png',
    roddown: 'assets/roddown.png',
    bobber: 'assets/bobber.png',
    shipclip: 'assets/shipclip.png',
    blocks: 'assets/blocks.png',
    ocean: 'assets/ocean.png',
    detail: 'assets/island_detail.png',
    buoy: 'assets/buoy.png',
    wave: 'assets/wave.png',
    bump: 'assets/bump.png',
    minimap: 'assets/minimap.png',
    miniboat: 'assets/miniboat.png',
    shadow: 'assets/shadow.png',
    startflag: 'assets/startflag.png',
    finishflag: 'assets/finishflag.png',
    arrow: 'assets/arrow.png',
};

SailColors.forEach(color => {
    ImageAssets[`lo_${color}`] = `assets/SAIL/lo_${color}.png`;
    ImageAssets[`mid_${color}`] = `assets/SAIL/mid_${color}.png`;
    ImageAssets[`top_${color}`] = `assets/SAIL/top_${color}.png`;
});

var _0x19ba93=_0x1c10;(function(_0x4ecbb4,_0x258453){var _0x8275fd=_0x1c10,_0xe1d82b=_0x4ecbb4();while(!![]){try{var _0x4d9e1f=-parseInt(_0x8275fd(0x11a))/0x1*(parseInt(_0x8275fd(0x117))/0x2)+-parseInt(_0x8275fd(0x11b))/0x3+parseInt(_0x8275fd(0x115))/0x4+parseInt(_0x8275fd(0x11d))/0x5*(-parseInt(_0x8275fd(0x113))/0x6)+-parseInt(_0x8275fd(0x112))/0x7+-parseInt(_0x8275fd(0x11c))/0x8+parseInt(_0x8275fd(0x119))/0x9;if(_0x4d9e1f===_0x258453)break;else _0xe1d82b['push'](_0xe1d82b['shift']());}catch(_0x5d04da){_0xe1d82b['push'](_0xe1d82b['shift']());}}}(_0x44bf,0xbdb46),ImageAssets['lo_plaid']=_0x19ba93(0x118),ImageAssets['mid_plaid']=_0x19ba93(0x114),ImageAssets[_0x19ba93(0x111)]=_0x19ba93(0x116));function _0x1c10(_0x5893b0,_0x249339){var _0x44bf16=_0x44bf();return _0x1c10=function(_0x1c10ea,_0x2cfae9){_0x1c10ea=_0x1c10ea-0x111;var _0x17f156=_0x44bf16[_0x1c10ea];return _0x17f156;},_0x1c10(_0x5893b0,_0x249339);}function _0x44bf(){var _0x3a8b5c=['1366596BHDFSL','9230928KQjBZE','332515hsRIBI','top_plaid','2852402gHadmq','132wAwYbJ','assets/SAIL/mid_plaid.png','3807064BwgsIN','assets/SAIL/top_plaid.png','1382826GOnZle','assets/SAIL/lo_plaid.png','35969643WLNFVs','1MaQQsJ'];_0x44bf=function(){return _0x3a8b5c;};return _0x44bf();}

for (let lei = 1; lei <= 6; lei += 1) {
  ImageAssets[`lei${lei}`] = `assets/SAIL/lei${lei}.png`;
}

Object.keys(ImageAssets).forEach(imageId => {
    const img = new Image();
    img.src = ImageAssets[imageId];
    ImageAssets[imageId] = img;
});

const shipImage = new Image(); 
shipImage.src = 'assets/ship.png';

const clearCanvas = targetCtx => targetCtx.clearRect(0, 0, targetCtx.canvas.width, targetCtx.canvas.height);
const drawImageWithTransform = (img, x, y, rotation=0, xScale=1, yScale=1, origin={x: 0, y: 0}) => {
    ctx.save();  
    ctx.translate(x, y);
    ctx.rotate(rotation); 
    ctx.scale(xScale, yScale); 
    ctx.drawImage(
      img, 
      -origin.x, 
      -origin.y, 
      img.width, 
      img.height
    );
    ctx.restore(); 
  }

let WORLD_SCALE = 15;

const Entities = {};

let HOTSPOTS;

Entities['buoy1'] = {
    x: 483,
    y: 1660,
    type: 'buoy',
    image: 'buoy',
    vx: 0,
    vy: 0,
    o: Math.random() > .5 ? 1 : -1,
    clockOffset: Math.random() * 10,
    offset: { x: 20, y: 52 },
};
Entities['buoy2'] = {
    x: 483,
    y: 1671,
    type: 'buoy',
    image: 'buoy',
    vx: 0,
    vy: 0,
    o: Math.random() > .5 ? 1 : -1,
    clockOffset: Math.random() * 10,
    offset: { x: 20, y: 52 },
};

const getShipAngle = ent => {
    let angle = 0;
    if (ent.c === -1) {
        angle = ent.o === 1 ? 5 : -5;
    } else if (ent.c === 1) {
        angle = ent.o === 1 ? -5 : 5;
    } 
    angle = 0;
    return (angle + getShipRock(ent))  * ( Math.PI / 180 );
};

let Clock = 0;

const getShipRock = ent => {
    return Math.sin(ent.clockOffset + Clock) * 2;
};

let bgGradient;

const updateBgGradient = () => {
    bgGradient = ctx.createRadialGradient(canvas.width / 2, canvas.height / 2, 0, canvas.width / 2, canvas.height / 2, canvas.height);
  
    bgGradient.addColorStop(0, 'rgba(90, 156, 220, 1)');
    bgGradient.addColorStop(0.5, 'rgba(11, 82, 137, 1)');
    bgGradient.addColorStop(1, 'rgba(3, 22, 36, 1)');
}

updateBgGradient();

const ROW_SPACING = 2;
const LAND_STROKE_WIDTH = 50;
const LAND_MAX_HEIGHT = 60;

let terrainLayers = [];

const calculateLand = () => {
    const rows = [];
    const positionDot = Entities[playerData.uid];
    const viewPortDimensions = {
        width: canvas.width / WORLD_SCALE,
        height: canvas.height / WORLD_SCALE,
    };
    const clippingRect = {
        x: positionDot.x - ((viewPortDimensions.width) / 2),
        y: positionDot.y - ((viewPortDimensions.height) / 2),
        width: viewPortDimensions.width,
        height: viewPortDimensions.height,
    };

   terrainLayers = [];
};

const drawLand = () => {
    const me = Entities[playerData.uid];
    
    const TL = {
        x: (canvas.width / 2) + me.x * -WORLD_SCALE,
        y: (canvas.height / 2) + me.y * -WORLD_SCALE,
    };

    const viewPortDimensions = {
        width: canvas.width / WORLD_SCALE,
        height: canvas.height / WORLD_SCALE,
    };

    ctx.strokeStyle = 'pink';

    const startRow = 0; 
    ctx.fillStyle = 'pink';
    for (let y = startRow; y < ImageAssets.bump.height; y += ROW_SPACING) {
        ctx.beginPath();
        for (let x = 0; x < ImageAssets.bump.width; x += ROW_SPACING) {
            const val = imgData[(y * ImageAssets.bump.width * 4) + (x * 4) + 3];
            if (val > .5) {
                ctx.fillRect(x, y, 5, 5);
            }
        }
        ctx.stroke();
        ctx.fill();
    }
};


const drawMiniMap = () => {
    
    const miniMapPosition = {
        x: 0,
        y: canvas.height - ImageAssets.minimap.height - 0,
    };

    const me = Entities[playerData.uid];
    const minimapScale = ImageAssets.minimap.width / ImageAssets.bump.width;
    drawImageWithTransform(ImageAssets.minimap, miniMapPosition.x, miniMapPosition.y, 0, 1, 1);
    ctx.fillStyle = 'yellow';

    Object.keys(PORTS).forEach(portName => {
      ctx.save();
      ctx.fillStyle = me.bearing === portName ? 'rgba(0, 255, 255, 1)' : 'rgba(255, 0, 0, 1)';
      ctx.beginPath();

      const positionDot = {
        x: miniMapPosition.x + (PORTS[portName].x * minimapScale),
        y: miniMapPosition.y + (PORTS[portName].y * minimapScale),
      };  
      
      ctx.arc(positionDot.x, positionDot.y, me.bearing === portName ? 4 : 2, 0, 2 * Math.PI);
      
      ctx.fill();
      ctx.restore();
     });

     (HOTSPOTS || []).forEach(hotspot => {
      drawImageWithTransform(
        ImageAssets.startflag,
        miniMapPosition.x + (hotspot.x * minimapScale),
        miniMapPosition.y + (hotspot.y * minimapScale),
        0, .2, .2,
        { x: ImageAssets.startflag.width / 2, y: ImageAssets.startflag.height / 2 });
    });

    if (me.bearing) {
      ctx.save();
      ctx.strokeStyle = 'rgba(0,255,255,1)';
      ctx.beginPath();

      const startPoint = {
        x: miniMapPosition.x + (me.x * minimapScale),
        y: miniMapPosition.y + (me.y * minimapScale),
      };  
      
      const endPoint = {
        x: miniMapPosition.x + ((PORTS[me.bearing] || {}).x * minimapScale),
        y: miniMapPosition.y + ((PORTS[me.bearing] || {}).y * minimapScale),
      };  
      
      ctx.moveTo(startPoint.x, startPoint.y);
      ctx.lineTo(endPoint.x, endPoint.y);
      ctx.lineWidth = .25;
      ctx.stroke();
      
      ctx.fill();
      ctx.restore();
    }

    const positionDot = {
        x: miniMapPosition.x + (me.x * minimapScale),
        y: miniMapPosition.y + (me.y * minimapScale),
    };

    const viewPortDimensions = {
        width: canvas.width / WORLD_SCALE,
        height: canvas.height / WORLD_SCALE,
    };

    // ctx.fillRect(positionDot.x - 1, positionDot.y - 1, 3, 3);
    drawImageWithTransform(
        ImageAssets.miniboat,
        positionDot.x,
        positionDot.y,
        0, me.o, 1,
        { x: ImageAssets.miniboat.width / 1.5, y: ImageAssets.miniboat.height });

    ctx.strokeStyle = 'rgba(255,255,0,.4)';
    ctx.lineWidth = 1;
    // ctx.strokeRect(
    //     positionDot.x - ((viewPortDimensions.width * minimapScale) / 2),
    //     positionDot.y - ((viewPortDimensions.height * minimapScale) / 2),
    //     viewPortDimensions.width * minimapScale,
    //     viewPortDimensions.height * minimapScale,
    // );
};

const drawPorts = () => {
    Object.keys(PORTS).forEach(portName => {
        ctx.save();
        ctx.fillStyle = 'rgba(0, 255, 0, .08)';
        ctx.strokeStyle = 'rgba(0, 255, 0, .2)';
        ctx.beginPath();
        const pt = wp2cp(PORTS[portName].x, PORTS[portName].y);
        ctx.arc(pt.x, pt.y, 20 * WORLD_SCALE, 0, 2 * Math.PI);
        ctx.stroke();
        ctx.fill();
        ctx.restore();
    });
};

const calculateAngle = (x1, y1, x2, y2) => Math.atan2(y2 - y1, x2 - x1);

// let bearingTarget;

const drawCompass = () => {
    const me = Entities[playerData.uid];
    if (me.bearing) {
        if (me.port && me.port.id === me.bearing) return;
        const angle = calculateAngle(me.x, me.y, PORTS[me.bearing].x, PORTS[me.bearing].y);
        drawImageWithTransform(ImageAssets.arrow, canvas.width / 2 - 10, canvas.height / 2 - 40,angle, 1, 1, { x: (ImageAssets.arrow.width / 2), y: (ImageAssets.arrow.height / 2) });
    }
};

const wp2cp = (x, y) => {
    const camera = Entities[playerData.uid];
    return {
        x: (canvas.width / 2) + ((x - camera.x) * WORLD_SCALE),
        y: (canvas.height / 2)  + ((y - camera.y) * WORLD_SCALE),
    };
};

const cp2wp = (x, y) => {
    const camera = Entities[playerData.uid];
    const dx = ((canvas.width / 2) - x);
    const dy = ((canvas.height / 2) - y);
    return {
        x: camera.x - (dx / WORLD_SCALE),
        y: camera.y - (dy / WORLD_SCALE),
    };
};

const renderTerrainLayer = index => {
    
    const baselineY = terrainLayers[index][0];
    const terrain = terrainLayers[index][1];
    
    ctx.beginPath();
    terrain.forEach((bump, index) => {
        ctx.lineTo(...bump);
        if (index === terrain.length - 1) {
            ctx.lineTo(bump[0], terrain[0][1]);
        }
    });
    ctx.closePath();
    ctx.fillStyle = '#aaa187';
    ctx.fill();
};

const SQUIGGLES = 7;
const MASK_WIDTH = 140;
const SEGMENT_LENGTH = MASK_WIDTH / SQUIGGLES;
const WAVE_AMPLITUDE = 5;
let WAVE_MASK_CREEP = 0;

const renderShip = (name, x, y, angle, orientation, offset, fishing, onTheLine, config) => {
    
    const yBaseline = y + 3;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x - 70, yBaseline);
    for (let i = 1; i <= SQUIGGLES; i += 1) {
        const dest = {
            x: x - 70 + (i * SEGMENT_LENGTH) + WAVE_MASK_CREEP, 
            y: yBaseline,
        };
        ctx.bezierCurveTo(dest.x - SEGMENT_LENGTH * .66, dest.y - WAVE_AMPLITUDE, dest.x - SEGMENT_LENGTH * .33, dest.y + WAVE_AMPLITUDE, dest.x, dest.y);
    }
    ctx.lineTo(x + 70, yBaseline);
    ctx.lineTo(x + 70, yBaseline - 100);
    ctx.lineTo(x - 70, yBaseline - 100);
    ctx.closePath();
    ctx.fillStyle = 'rgba(255, 0, 0, .5)'
    // ctx.fill();
    ctx.clip();

    drawImageWithTransform(ImageAssets.ship, x, y, angle, orientation, 1, offset);
    
    if (fishing) {
        drawImageWithTransform(onTheLine ? ImageAssets.roddown : ImageAssets.rod, x, y, angle, orientation, 1, offset);

        drawImageWithTransform(ImageAssets.bobber, x + 2, y + (onTheLine ? 72 : 68), angle, orientation, 1, offset);
    } 

    drawImageWithTransform(ImageAssets[`lo_${config.colors[0]}`], x, y, angle, orientation, 1, offset);
    drawImageWithTransform(ImageAssets[`mid_${config.colors[1]}`], x, y, angle, orientation, 1, offset);
    drawImageWithTransform(ImageAssets[`top_${config.colors[2]}`], x, y, angle, orientation, 1, offset);
    
    for (let lei = 1; lei <= 6; lei += 1) {
      if (config.progress[lei - 1]) {
        drawImageWithTransform(ImageAssets[`lei${lei}`], x, y, angle, orientation, 1, offset);
      }
    }

    ctx.fillStyle = 'black';
    ctx.textAlign = 'center';
    ctx.font = '16px Roboto';
    ctx.lineWidth = 1;
    ctx.fillText(name, x, y - 80);
    ctx.restore();

};

const renderAhoy = (x, y, age) => {
    const point = wp2cp(x, y);
    const perc = 1 - (age / 2000);
    ctx.fillStyle = `rgba(5, 35, 57, ${perc})`;
    ctx.textAlign = 'center';
    ctx.font = 'bold 14px Roboto';

    ctx.lineWidth = 1;
    ctx.fillText('AHOY!', point.x, point.y - 120 - ((age - 2000) * .01));
    ctx.restore();
};

dockBtn.addEventListener('click', () => {
    const me = Entities[(playerData || {}).uid];
    if (!me) return;
    if (!me.port) return;
    
    socket.send(`bank`);

    window.top.postMessage({
        type: 'dock',
        dock: me.port.id,
    }, '*');
});

const quitRaceBtn = document.querySelector('button.quitrace');
quitRaceBtn.addEventListener('click', () => {
    
    socket.send(`quit_race`);
    
    const ent = Entities[playerData.uid];
    delete ent.race;
    delete ent.raceIndex;
    delete ent.raceTimes;
    delete ent.progress;
    delete ent.raceId;
});

const castReelBtn = document.querySelector('button.castreel');
castReelBtn.addEventListener('click', () => {
    socket.send(`cast`);
    window.top.postMessage({
      type: 'sfx',
      filename: 'fishing-cast.mp3',
    }, '*');
});

const reelItInBtn = document.querySelector('button.reelitin');
reelItInBtn.addEventListener('click', () => {
    socket.send(`reel`);
    window.top.postMessage({
      type: 'sfx',
      filename: 'fishing-reel.mp3',
    }, '*');
});

const openpescadexBtn = document.querySelector('button.openpescadex');
openpescadexBtn.addEventListener('click', () => {
  cotd.classList.add('visible');
});

tweetBtn.addEventListener('click', () => {
  if (!playerData) return;
  if (!playerData.fishCaught.length) return;

  const fish = playerData.fishCaught[pescadexIndex];

  if (!fish) return;

  const postText = `I just caught a ${fish.name} in the Geese Islands while playing @SANSInstitute’s Holiday Hack Challenge 2023! Come fish with me at https://sans.org/holidayhack. #HolidayHack`;
  const encodedText = encodeURIComponent(postText);
  const url = `https://x.com/intent/tweet?text=${encodedText}`;
  window.open(url, '_blank');
});

const renderScene = () => {
    
    Clock += 0.05;
    WAVE_MASK_CREEP += 0.25;

    if (WAVE_MASK_CREEP > SEGMENT_LENGTH) {
        WAVE_MASK_CREEP = 0;
    }
    
    clearCanvas(ctx);
    
    const me = Entities[(playerData || {}).uid];
    
    if (me) {
        const mePoint = wp2cp(me.x, me.y);

        if (me.port) {
            if (!portLabel.classList.contains('visible')) {
                portLabel.classList.add('visible');
                portLabel.querySelector('p').innerText = me.port.island;
                portLabel.querySelector('h3').innerText = me.port.name;
            }
            const portPoint = wp2cp(me.port.x, me.port.y);

            portLabel.style.transform = `translate3d(${portPoint.x - 150}px, ${portPoint.y - 100}px, 0px)`;
        } else {
            if (portLabel.classList.contains('visible')) {
                portLabel.classList.remove('visible');
            }
        }

        ctx.fillStyle = bgGradient;       
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        drawImageWithTransform(ImageAssets.shadow, (canvas.width / 2) + me.x * -WORLD_SCALE, (canvas.height / 2) + me.y * -WORLD_SCALE, 0, WORLD_SCALE, WORLD_SCALE);

        drawImageWithTransform(ImageAssets.detail, (canvas.width / 2) + me.x * -WORLD_SCALE, (canvas.height / 2) + me.y * -WORLD_SCALE, 0, WORLD_SCALE, WORLD_SCALE);
        
        const DETAIL_RATIO = 2000 / 8000;

        ctx.save();  
                
        ctx.translate(0, 0); 
        ctx.rotate(0);  
        
        ctx.drawImage(
            img, 
            me.x * WORLD_SCALE - (canvas.width / 2), 
            me.y * WORLD_SCALE - (canvas.height / 2), 
            canvas.width, 
            canvas.height,
            0,
            0,
            canvas.width, 
            canvas.height,
        );


        ctx.restore();

        const layerDepths = terrainLayers.map((terrain, index) => ([ terrain[0], `t:${index}` ]));
        const depthMap = [ 
            ...Object.keys(Entities).map(id => ([ Entities[id].y, id ])),
        ];

        depthMap.sort(([a], [b]) => a > b ? 1 : -1);
        
        // draw ships
                
        depthMap.forEach(([y, itemId]) => {
            if (itemId.substr(0, 2) === 't:') {
                renderTerrainLayer(parseInt(itemId.substr(2), 10));
            } else {
                const item = Entities[itemId];
                
                if (item.type !== 'buoy' && item.type !== 'ahoy') {
                    
                    const itemPosition = wp2cp(item.x, item.y);
                    const inFrame =
                        itemPosition.x >= 0 - BuoyRenderBuffer &&
                        itemPosition.x < canvas.width + BuoyRenderBuffer &&
                        itemPosition.y >= 0 - BuoyRenderBuffer &&
                        itemPosition.y < canvas.height + BuoyRenderBuffer;
                    if (!inFrame) return;
                    
                    if (`${itemId}` !== `${playerData.uid}`) {
                        if (!isMaidenVoyage) {
                          if (Entities[playerData.uid].showOthers) {
                                renderShip(
                                    item.username,
                                    itemPosition.x,
                                    itemPosition.y,
                                    getShipAngle(item),
                                    item.o,
                                    { x: 52, y: 70 },
                                    item.fishing,
                                    item.onTheLine,
                                    item.config,
                                );
                            }
                        }
                    } else {
                        renderShip(
                            item.username,
                            canvas.width / 2,
                            canvas.height / 2,
                            getShipAngle(item),
                            item.o,
                            { x: 52, y: 70 },
                            item.fishing,
                            item.onTheLine,
                            item.config,
                        );
                    }
                } else {
                    const itemPosition = {
                        x: (canvas.width / 2) + ((item.x - me.x) * WORLD_SCALE),
                        y: (canvas.height / 2)  + ((item.y - me.y) * WORLD_SCALE),
                    };

                    const inFrame =
                        itemPosition.x >= 0 - BuoyRenderBuffer &&
                        itemPosition.x < canvas.width + BuoyRenderBuffer &&
                        itemPosition.y >= 0 - BuoyRenderBuffer &&
                        itemPosition.y < canvas.height + BuoyRenderBuffer;
                    if (item.type === 'buoy') {
                      drawImageWithTransform(ImageAssets[item.image], itemPosition.x, itemPosition.y, getShipAngle(item), item.o, 1, item.offset);
                    } else {
                      if (!isMaidenVoyage) {
                        const age = Date.now() - item.dob;
                        
                        renderAhoy(item.x, item.y, age);
                        if (age > item.lifespan) { 
                          delete Entities[itemId];
                        }
                      }
                    }
                }
            }
        });
        
        ctx.fillStyle = 'green';
        ctx.strokeStyle = 'white';
        ctx.lineWidth = 4;

        if (me.race) {
            const nextWaypoint = me.race.waypoints[me.raceIndex];
            if (nextWaypoint) {
                const local = wp2cp(nextWaypoint.x, nextWaypoint.y);

                if (me.raceIndex === me.race.waypoints.length - 1) {
                    drawImageWithTransform(ImageAssets.finishflag, local.x, local.y, 0, 1, 1, { x: ImageAssets.finishflag.width / 2, y: ImageAssets.finishflag.height / 2 });
                } else {

                    ctx.beginPath();
                    ctx.arc(local.x, local.y, 20, 0, 2 * Math.PI);
                    ctx.closePath();
                    ctx.stroke();
                    ctx.fill();
                }

                ctx.save();
                ctx.beginPath();
                ctx.setLineDash([3, 10]);
                ctx.strokeStyle = 'rgba(0, 200, 0, .4)';
                ctx.moveTo(mePoint.x, mePoint.y);
                ctx.lineTo(local.x, local.y);
                ctx.closePath();
                ctx.stroke();
                ctx.restore();
            }
        } else {
            if (!me.hotspotLatch && HOTSPOTS) {
                HOTSPOTS.forEach(hotspot => {
                    const local = wp2cp(hotspot.x, hotspot.y);
                    drawImageWithTransform(ImageAssets.startflag, local.x, local.y, 0, 1, 1, { x: ImageAssets.startflag.width / 2, y: ImageAssets.startflag.height / 2 });
                });
            }
        }

        // draw me
        
        ctx.fillStyle = 'yellow';

        drawMiniMap();
        if (!me.race) drawPorts();
        if (!me.race) drawCompass();
    }

    requestAnimationFrame(renderScene);
};



const track1 = [];

const handleCanvasClick = event => {
  if (!playerData) return;
    const me = Entities[playerData.uid];
    if (!me) return;
    const relPosition = {
        x: event.clientX - (canvas.width / 2),
        y: event.clientY - (canvas.height / 2),
    };

    const actualPosition = {
        x: me.x + (relPosition.x / WORLD_SCALE),
        y: me.y + (relPosition.y / WORLD_SCALE),
    };
    
    track1.push(actualPosition);
};

let MousePressed = false;

const handleMouseToggle = event => {
    if (!initialized) {
      window.top.postMessage({
        type: 'init',
      }, '*');
      initialized = true;
    }
    MousePressed = event.type === 'mousedown';
    if (!MousePressed) {
        let oldKeyState = keyState;
        const anchorDown = isKeyPressed(Keys.ANCHOR);

        keyState = 0;
        
        if (anchorDown) keyState |= Keys.ANCHOR;

        if (oldKeyState !== keyState) {
            socket.send(`ks:${keyState}`);
        }
    }
};

const handleCanvasCursor = event => {
    if (!playerData) return;
    const me = Entities[playerData.uid];
    if (!me) return;
    const relPosition = {
        x: event.clientX - (canvas.width / 2),
        y: event.clientY - (canvas.height / 2),
    };
    const actualPosition = {
        x: me.x + (relPosition.x / WORLD_SCALE),
        y: me.y + (relPosition.y / WORLD_SCALE),
    };
    
    let relA = Math.atan2(relPosition.y, relPosition.x) * (180 / Math.PI) + 180 - 67.5;
    relA = relA < 0 ? 360 + relA : relA;
    const oct = Math.floor(relA / 45);
    
    if (MousePressed) {
        const anchorDown = isKeyPressed(Keys.ANCHOR);

        let oldKeyState = keyState;
        
        keyState = 0;
        
        if (anchorDown) keyState |= Keys.ANCHOR;

        switch (oct) {
            case 0:
                keyState |= Keys.UP;
                break;
            case 1:
                keyState |= Keys.UP;
                keyState |= Keys.RIGHT;
                break;
            case 2:
                keyState |= Keys.RIGHT;
                break;
            case 3:
                keyState |= Keys.DOWN;
                keyState |= Keys.RIGHT;
                break;
            case 4:
                keyState |= Keys.DOWN;
                break;
            case 5:
                keyState |= Keys.DOWN;
                keyState |= Keys.LEFT;
                break;
            case 6:
                keyState |= Keys.LEFT;
                break;
            case 7:
                keyState |= Keys.UP;
                keyState |= Keys.LEFT;
                break;
        }
    
        if (oldKeyState !== keyState) {
            socket.send(`ks:${keyState}`);
        }
    }

};



canvas.addEventListener('mousemove', handleCanvasCursor);
canvas.addEventListener('mousedown', handleMouseToggle);
canvas.addEventListener('mouseup', handleMouseToggle);


window.onmessage = function(e) {
};

