<?php

declare(strict_types=1);

namespace OCA\OrganizationFolders\Model;

use OCP\IUser;
use OCP\IUserManager;

use OCA\GroupFolders\ACL\UserMapping\IUserMapping;
use OCA\GroupFolders\ACL\UserMapping\UserMapping;

use OCA\OrganizationFolders\Enum\PrincipalType;

class UserPrincipal extends Principal {
	private ?IUser $user = null;
	private bool $resolved = false;

	public function __construct(
		private IUserManager $userManager,
		private string $id,
	) {
	}

	/**
	 * Resolve the backing user lazily. Loading the user (and computing validity)
	 * is deferred until something actually needs it, so bulk-loading user members
	 * for the permission/ACL apply path does not trigger one IUserManager lookup
	 * per member (those paths only use getId()/toGroupfolderAclMapping()).
	 */
	private function resolve(): void {
		if($this->resolved) {
			return;
		}
		try {
			$this->user = $this->userManager->get($this->id);
		} catch (\Exception $e) {
			$this->user = null;
		}
		$this->valid = !is_null($this->user);
		$this->resolved = true;
	}

	public function isValid(): bool {
		$this->resolve();
		return $this->valid;
	}

	public function getType(): PrincipalType {
		return PrincipalType::USER;
	}

	public function getId(): string {
		return $this->id;
	}

	public function getFriendlyName(): string {
		$this->resolve();
		return $this->user?->getDisplayName() ?? $this->getId();
	}

	public function getNumberOfUsersContained(): int {
		return $this->isValid() ? 1 : 0;
	}

	/**
	 * @return IUser[]
	 */
	public function getUsersContained(): array {
		$this->resolve();
		if($this->valid) {
			return [$this->user];
		} else {
			return [];
		}
	}

	public function toGroupfolderAclMapping(): ?IUserMapping {
		if($this->id != '') {
			return new UserMapping(type: "user", id: $this->id, displayName: null);
		} else {
			return null;
		}
	}

	public function toDavPrincipalURI(): string {
		return "principals/users/" . $this->id;
	}

	public function isEquivalent(Principal $principal): bool {
		if($this->isValid() && $principal->isValid()) {
			if($principal instanceof UserPrincipal) {
				return $principal->getId() === $this->getId();
			}
		}

		return false;
	}

	public function containsPrincipal(Principal $principal, bool $skipExpensiveOperations = false): bool {
		return $this->isEquivalent($principal);
	}
}