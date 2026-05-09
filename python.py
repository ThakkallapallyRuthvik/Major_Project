def solve_n_queens(n):
    """
    Solve the N-Queens problem using backtracking.
    Place N queens on an NxN board such that no two queens attack each other.
    """
    results = []
    board = [-1] * n  # board[i] = column position of queen in row i

    def is_safe(row, col):
        for r in range(row):
            c = board[r]
            # Check same column or diagonal attack
            if c == col or abs(c - col) == abs(r - row):
                return False
        return True

    def backtrack(row):
        if row == n:
            # All queens placed — record solution
            results.append(board[:])
            return

        for col in range(n):
            if is_safe(row, col):
                board[row] = col        # Place queen
                backtrack(row + 1)      # Recurse to next row
                board[row] = -1         # Remove queen (backtrack)

    backtrack(0)
    return results


def print_board(board):
    n = len(board)
    for row in range(n):
        line = ""
        for col in range(n):
            line += "Q " if board[row] == col else ". "
        print(line)
    print()


# --- Run it ---
n = 4
solutions = solve_n_queens(n)
print(f"{n}-Queens Problem: {len(solutions)} solution(s) found\n")

for i, sol in enumerate(solutions):
    print(f"Solution {i + 1}:")
    print_board(sol)
