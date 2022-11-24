import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

const categories = [
	{ label: 'Shopping', icon: 'user' },
	{ label: 'Bills', icon: 'user' },
	{ label: 'Investment', icon: 'user' },
	{ label: 'Travel', icon: 'user' },
];

export const register = async (req, res) => {
	const { firstName, lastName, email, password } = req.body;
	const userExist = await User.findOne({ email });

	if (userExist) {
		res.status(406).json('User is already exist');
		return;
	}

	const saltRounds = 10;
	const salt = await bcrypt.genSaltSync(saltRounds);
	const hashedPassword = await bcrypt.hashSync(password, salt);

	const user = await User({ firstName, lastName, email, password: hashedPassword, categories });
	await user.save();
	res.status(201).json({ message: 'User is created' });
};

export const login = async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });

	if (!user) {
		res.status(406).json('Cresidential not found');
		return;
	}

	const match = await bcrypt.compare(password, user.password);

	if (!match) {
		res.status(406).json('Cresidential not found');
		return;
	}

	const payload = {
		username: email,
		_id: user._id,
	};
	const token = jwt.sign(payload, process.env.JWT_SECRET);
	res.json({ message: 'Logged in successfully', token, user });
};
