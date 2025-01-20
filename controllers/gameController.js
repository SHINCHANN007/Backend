// controllers/gameController.js
const Game = require('../models/Game');
const User = require('../models/user'); // Import the User model

// Add or Update High Score
const addOrUpdateHighScore = async (req, res) => {
  const { username, gameName, score } = req.body;

  try {
    // Check if the username exists in the User collection
    const userExists = await User.findOne({ username });
    if (!userExists) {
      return res.status(404).json({ message: 'Username does not exist' });
    }

    // Check if there's already a high score for this user and game
   if(gameName == "dogGame"){
      const existingScore = await Game.findOne({ username, gameName });

      if (existingScore) {
        // Update the score only if the new score is higher
        if (score > existingScore.score) {
          existingScore.score = score;
          await existingScore.save();
          return res.status(200).json({ message: 'High score updated successfully', score: existingScore });
        } else {
          return res.status(200).json({ message: 'Existing high score is higher, no update made', score: existingScore });
        }
      } else {
        // If no score exists, create a new one
        const newScore = new Game({ username, gameName, score });
        await newScore.save();
        res.status(201).json({ message: 'High score saved successfully', score: newScore });
    }
   }
    else if(gameName == "gorillaGame"){
      const existingScore2 = await Game.findOne({username, gameName});

      if(existingScore2){
        existingScore2.score += 1;
        await existingScore2.save();
        return res.status(200).json({ message: 'High score updated successfully', score: existingScore2 });
      }
      else{
        const newScore2 = new Game({ username, gameName, score });
        await newScore2.save();
        res.status(201).json({ message: 'High score saved successfully', score: newScore2 });
        
      }
      

      
      }

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Get top high scores for a specific game
const getUserHighScore = async (req, res) => {
  const { username, gameName } = req.body; // Retrieve from body

  try {
      // Find the high score for the specified user and game
      let userScore = await Game.findOne({ username, gameName });

      if (!userScore) {
          // If no score found, create and save dummy data with a score of 0
          userScore = new Game({
              username,
              gameName,
              score: 0 // Default score value
          });
          
          await userScore.save();

          console.log("Since no game played, made dummy data");
      }

      res.status(200).json(userScore);
  } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  addOrUpdateHighScore,
  getUserHighScore,
};
