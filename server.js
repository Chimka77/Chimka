const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Platform Wallet Configuration
const PLATFORM_WALLET = "UQB4g1EPXqzBL3mVkscXd8CY8LNck-uJWiBqpJv_j1c9yYW5";
const RAKE_PERCENTAGE = 0.10; // 10% platform fee

// Active rooms and lobbies store
const rooms = {};

app.get('/', (req, res) => {
  res.send({ status: "Beach Buggy Racing Backend Running", wallet: PLATFORM_WALLET });
});

io.on('connection', (socket) => {
  console.log(`Player connected: ${socket.id}`);

  // Create custom betting room
  socket.on('create_room', ({ stakeAmount, mapName }) => {
    const roomId = Math.random().toString(36.substring(2, 8).toUpperCase());
    rooms[roomId] = {
      host: socket.id,
      stake: stakeAmount || 3.0,
      map: mapName || 'Stadium Arena',
      players: [socket.id],
      status: 'waiting'
    };
    socket.join(roomId);
    socket.emit('room_created', { roomId, stake: rooms[roomId].stake });
    console.log(`Room created: ${roomId} with stake $${rooms[roomId].stake}`);
  });

  // Join existing room
  socket.on('join_room', ({ roomId }) => {
    if (rooms[roomId] && rooms[roomId].status === 'waiting') {
      rooms[roomId].players.push(socket.id);
      socket.join(roomId);
      io.to(roomId).emit('player_joined', { playersCount: rooms[roomId].players.length });
      
      // If room has enough players, calculate pool and take 10% rake for your wallet
      if (rooms[roomId].players.length >= 2) {
        rooms[roomId].status = 'racing';
        const totalPool = rooms[roomId].stake * rooms[roomId].players.length;
        const platformFee = totalPool * RAKE_PERCENTAGE;
        const prizePool = totalPool - platformFee;

        console.log(`Match starting in room ${roomId}! Total Pool: $${totalPool}, Rake to ${PLATFORM_WALLET}: $${platformFee}`);

        io.to(roomId).emit('start_race', { 
          prizePool, 
          platformFeeDestination: PLATFORM_WALLET 
        });
      }
    } else {
      socket.emit('error', { message: "Room not found or race already started." });
    }
  });

  // Handle player vehicle movement and trap placements in real-time
  socket.on('player_update', (data) => {
    socket.to(data.roomId).emit('opponent_update', data);
  });

  socket.on('deploy_trap', (data) => {
    // data: { roomId, trapType, position }
    io.to(data.roomId).emit('spawn_trap', data);
  });

  socket.on('disconnect', () => {
    console.log(`Player disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
