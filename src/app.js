import express from 'express';
import mongoose from 'mongoose';
import usersRouter from './routes/user.routes.js'


const app = express();
const SERVER_PORT = 9090;

//Preparar la configuracion del servidor para recibir objetos JSON.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));





//Definir rutas
app.get('/ping', (req, res) => {
    res.send("pong")
})


app.use('/api/users', usersRouter)




// Server listen
app.listen(SERVER_PORT, () => {
    console.log(`Server is running on port ${SERVER_PORT}`);
});


// Conectamos la base de datos
const DB_PATH = 'mongodb://localhost:27017/clase_00?retryWrites=true&w=majority'
const connectMongoDB = async () => {
    try {
        await mongoose.connect(DB_PATH)
        console.log("Connected to MongoDB");
    } catch (error) {
        console.log("Failed to connect to MongoDB");
        process.exit();
    }
}
connectMongoDB();