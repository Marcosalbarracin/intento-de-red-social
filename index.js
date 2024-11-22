const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const connection = require('./config/database');
const { authenticate } = require('./middleware/authenticate');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key';

app.use(bodyParser.json());

// Endpoint para registrar un nuevo usuario
app.post('/api/usuarios/register', (req, res) => {
  const { nombre, nickname, mail, password, avatar } = req.body;
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: 'Error al encriptar la contraseña' });

    const query = 'INSERT INTO usuarios (nombre, nickname, mail, password, avatar) VALUES (?, ?, ?, ?, ?)';
    connection.query(query, [nombre, nickname, mail, hashedPassword, avatar], (err, results) => {
      if (err) return res.status(500).json({ error: 'Error al registrar el usuario' });

      res.status(201).json({ message: 'Usuario registrado con éxito', usuarioId: results.insertId });
    });
  });
});

// Endpoint para autenticar un usuario
app.post('/api/usuarios/login', (req, res) => {
  const { mail, password } = req.body;
  const query = 'SELECT * FROM usuarios WHERE mail = ?';
  connection.query(query, [mail], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al autenticar el usuario' });
    if (results.length === 0) return res.status(400).json({ error: 'Usuario no encontrado' });

    const usuario = results[0];
    bcrypt.compare(password, usuario.password, (err, isMatch) => {
      if (err || !isMatch) return res.status(400).json({ error: 'Contraseña incorrecta' });

      const token = jwt.sign({ id: usuario.id }, secretKey, { expiresIn: '1h' });
      res.status(200).json({ message: 'Usuario autenticado con éxito', token });
    });
  });
});

// Endpoint para listar todos los usuarios
app.get('/api/usuarios', (req, res) => {
  const query = 'SELECT * FROM usuarios';
  connection.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener los usuarios' });

    res.status(200).json(results);
  });
});

// Endpoint para actualizar el perfil del usuario autenticado
app.put('/api/usuarios/me', authenticate, (req, res) => {
  const { nombre, avatar } = req.body;
  const query = 'UPDATE usuarios SET nombre = ?, avatar = ? WHERE id = ?';
  connection.query(query, [nombre, avatar, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al actualizar el perfil' });

    res.status(200).json({ message: 'Perfil actualizado con éxito' });
  });
});

// Endpoint para crear un nuevo post
app.post('/api/posts', authenticate, (req, res) => {
  const { titulo, contenido } = req.body;
  const query = 'INSERT INTO posts (titulo, contenido, id_usuario) VALUES (?, ?, ?)';
  connection.query(query, [titulo, contenido, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al crear el post' });

    res.status(201).json({ postId: results.insertId });
  });
});

// Endpoint para listar todos los posts
app.get('/api/posts', authenticate, (req, res) => {
  const query = 'SELECT * FROM posts';
  connection.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener los posts' });

    res.status(200).json(results);
  });
});

// Endpoint para modificar un post
app.put('/api/posts/:id', authenticate, (req, res) => {
  const { titulo, contenido } = req.body;
  const query = 'UPDATE posts SET titulo = ?, contenido = ? WHERE id = ? AND id_usuario = ?';
  connection.query(query, [titulo, contenido, req.params.id, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al actualizar el post' });

    res.status(200).json({ message: 'Post actualizado con éxito' });
  });
});

// Endpoint para eliminar un post
app.delete('/api/posts/:id', authenticate, (req, res) => {
  const query = 'DELETE FROM posts WHERE id = ? AND id_usuario = ?';
  connection.query(query, [req.params.id, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al eliminar el post' });

    res.status(200).json({ message: 'Post eliminado con éxito' });
  });
});

// Endpoint para mostrar un post específico
app.get('/api/posts/:id', authenticate, (req, res) => {
  const query = 'SELECT * FROM posts WHERE id = ? AND id_usuario = ?';
  connection.query(query, [req.params.id, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener el post' });
    if (results.length === 0) return res.status(404).json({ error: 'Post no encontrado' });

    res.status(200).json(results[0]);
  });
});

// Endpoint para mostrar los posts de un usuario específico
app.get('/api/posts/user-posts/:id', authenticate, (req, res) => {
  const query = 'SELECT * FROM posts WHERE id_usuario = ?';
  connection.query(query, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener los posts' });

    res.status(200).json(results);
  });
});

// Endpoint para agregar una nueva relación de seguimiento
app.post('/api/following', authenticate, (req, res) => {
  const { id_usuario_seguido } = req.body;
  if (req.user.id === id_usuario_seguido) {
    return res.status(400).json({ error: 'No puedes seguirte a ti mismo' });
  }
  const query = 'INSERT INTO following (id_usuario, id_usuario_seguido) VALUES (?, ?)';
  connection.query(query, [req.user.id, id_usuario_seguido], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al seguir al usuario' });

    res.status(201).json({ followId: results.insertId });
  });
});

// Endpoint para eliminar una relación de seguimiento
app.delete('/api/following', authenticate, (req, res) => {
  const { id_usuario_seguido } = req.body;
  const query = 'DELETE FROM following WHERE id_usuario = ? AND id_usuario_seguido = ?';
  connection.query(query, [req.user.id, id_usuario_seguido], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al eliminar la relación de seguimiento' });

    res.status(200).json({ message: 'Relación de seguimiento eliminada con éxito' });
  });
});

// Endpoint para listar a los usuarios que sigo
app.get('/api/following/following', authenticate, (req, res) => {
  const query = 'SELECT * FROM following WHERE id_usuario = ?';
  connection.query(query, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener la lista de usuarios seguidos' });

    res.status(200).json(results);
  });
});

// Endpoint para listar a los usuarios que me siguen
app.get('/api/following/followers', authenticate, (req, res) => {
  const query = 'SELECT * FROM following WHERE id_usuario_seguido = ?';
  connection.query(query, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener la lista de seguidores' });

    res.status(200).json(results);
  });
});

// Endpoint para listar a los usuarios con seguimiento mutuo
app.get('/api/following/mutual', authenticate, async (req, res) => {
    try {
      const followingQuery = 'SELECT * FROM following WHERE id_usuario = ?';
      const followersQuery = 'SELECT * FROM following WHERE id_usuario_seguido = ?';
  
      const followingResults = await new Promise((resolve, reject) => {
        connection.query(followingQuery, [req.user.id], (err, results) => {
          if (err) reject(err);
          resolve(results);
        });
      });
  
      const followersResults = await new Promise((resolve, reject) => {
        connection.query(followersQuery, [req.user.id], (err, results) => {
          if (err) reject(err);
          resolve(results);
        });
      });
  
      const mutuals = followingResults.filter(f =>
        followersResults.some(f2 => f.id_usuario_seguido === f2.id_usuario)
      );
  
      res.status(200).json(mutuals);
    } catch (error) {
      res.status(500).json({ error: 'Error al obtener la lista de seguimiento mutuo' });
    }
  });
  