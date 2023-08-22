// // server.js
// const jsonServer = require('json-server')
// const server = jsonServer.create()
// const router = jsonServer.router('db.json')
// const middlewares = jsonServer.defaults()
// const port = process.env.PORT || 4000

// server.use(middlewares)
// server.use(router)
// server.listen(port, () => {
// 	console.log('JSON Server is running ' + port)
// })

const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const port = process.env.PORT || 4000;
const secretKey = crypto.randomBytes(32).toString('hex'); // Секретний ключ для підпису токенів

server.use(middlewares);
server.use(jsonServer.bodyParser);

// Middleware для створення та перевірки токенів
server.use((req, res, next) => {
	if (req.method === 'POST' && req.path === '/login') {
		const { email, password } = req.body;
		// Перевірка логіна і пароля
		if (isValidLogin(email, password)) {
			const token = jwt.sign({ email }, secretKey, { expiresIn: '1h' });
			res.json({ token });
		} else {
			res.status(401).json({ message: 'Invalid credentials' });
		}
	} else {
		// Захищені маршрути: перевіряємо наявність і валідність токену
		const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
		if (token) {
			jwt.verify(token, secretKey, (err, decoded) => {
				if (err) {
					return res.status(401).json({ message: 'Invalid token' });
				} else {
					req.user = decoded;
					next();
				}
			});
		} else {
			return res.status(401).json({ message: 'No token provided' });
		}
	}
});

// Приклад функції для перевірки логіна та пароля
function isValidLogin(email, password) {
	// Тут ви повинні реалізувати логіку перевірки логіна та пароля
	// Це може бути зв'язано з базою даних або іншим механізмом аутентифікації
	const users = require('./db.json').users;
	const user = users.find(u => u.email === email && u.password === password);
	return user !== undefined;
}

server.use(router);

server.listen(port, () => {
	console.log('JSON Server is running on port ' + port);
});

// Нова функція для отримання інформації про користувача
function getUser(req, res, next) {
	if (req.headers.authorization && req.headers.authorization.split(' ')[1]) {
		jwt.verify(req.headers.authorization.split(' ')[1], secretKey, (err, decoded) => {
			if (err) {
				return res.status(401).json({ message: 'Invalid token' });
			} else {
				req.user = decoded;
				next();
			}
		});
	} else {
		return res.status(401).json({ message: 'No token provided' });
	}
}

// Додаємо маршрут для отримання інформації про користувача
server.use('/users', getUser, (req, res) => {
	const user = req.user;
	res.json({ user });
});