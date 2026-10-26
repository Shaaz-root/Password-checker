import getpass

from passcheck.strength import check_strength


def main() -> None:
    print("=== Password Strength Checker ===")
    print("Type 'q' to quit.\n")

    while True:
        # getpass hides what you type. If you want to see it, use input() instead.
        password = getpass.getpass("Enter a password: ")

        if password.lower() == "q":
            print("Goodbye!")
            break

        result = check_strength(password)

        print(f"\nLength:   {result.length}")
        print(f"Entropy:  {result.entropy_bits} bits")
        print(f"Rating:   {result.rating} ({result.score}/4)")

        if result.score >= 3:
            print("Verdict:  STRONG password\n")
        else:
            print("Verdict:  NOT strong enough")
            for tip in result.feedback:
                print(f"  - {tip}")
            print()


if __name__ == "__main__":
    main()