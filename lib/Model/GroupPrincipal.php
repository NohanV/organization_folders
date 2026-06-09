<?php

declare(strict_types=1);

namespace OCA\OrganizationFolders\Model;

use OCP\IGroupManager;
use \OCP\IGroup;

use OCA\OrganizationFolders\Enum\PrincipalType;

class GroupPrincipal extends PrincipalBackedByGroup {
	private ?IGroup $group = null;
	private bool $resolved = false;

	public function __construct(
		IGroupManager $groupManager,
		private string $id,
	) {
		parent::__construct($groupManager);
	}

	/**
	 * Resolve the backing group lazily. Loading the group (and computing validity)
	 * is deferred until something actually needs it, so bulk-loading group members
	 * for the permission/ACL apply path does not trigger one IGroupManager lookup
	 * per member (those paths only use getId()/getBackingGroupId()).
	 */
	private function resolve(): void {
		if($this->resolved) {
			return;
		}
		try {
			$this->group = $this->groupManager->get($this->id);
		} catch (\Exception $e) {
			$this->group = null;
		}
		$this->valid = !is_null($this->group);
		$this->resolved = true;
	}

	public function isValid(): bool {
		$this->resolve();
		return $this->valid;
	}

	public function getType(): PrincipalType {
		return PrincipalType::GROUP;
	}

	public function getId(): string {
		return $this->id;
	}

	public function getFriendlyName(): string {
		$this->resolve();
		return $this->group?->getDisplayName() ?? $this->getId();
	}

	public function getBackingGroupId(): string {
		return $this->getId();
	}

	public function getBackingGroup(): ?IGroup {
		$this->resolve();
		return $this->group;
	}
}